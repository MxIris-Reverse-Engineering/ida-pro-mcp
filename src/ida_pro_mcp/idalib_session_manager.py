"""IDALib Session Manager - Multi-binary management for headless MCP server

This module provides session management for multiple IDA databases in idalib mode.
Each session represents an opened binary with its own IDA database instance.
"""

import os
import uuid
import threading
import logging
from pathlib import Path
from typing import Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

import idapro
import ida_auto

logger = logging.getLogger(__name__)


@dataclass
class IDASession:
    """Represents a single IDA database session"""

    session_id: str
    input_path: Path
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    is_analyzing: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert session to dictionary format"""
        return {
            "session_id": self.session_id,
            "input_path": str(self.input_path),
            "filename": self.input_path.name,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "is_analyzing": self.is_analyzing,
            "metadata": self.metadata,
        }


class IDASessionManager:
    """Manages multiple IDA database sessions for idalib mode.

    Design:
    - `_sessions` stores all known session metadata.
    - `_active_session_id` tracks the database currently opened in the idalib process.
    - `_context_bindings` maps MCP transport context IDs to session IDs.
    """

    def __init__(self):
        self._sessions: Dict[str, IDASession] = {}
        self._active_session_id: Optional[str] = None
        self._context_bindings: Dict[str, str] = {}
        self._lock = threading.RLock()
        logger.info("IDASessionManager initialized")

    def open_binary(
        self,
        input_path: Path | str,
        run_auto_analysis: bool = True,
        session_id: Optional[str] = None,
    ) -> str:
        """Open a binary file and create a new session

        Args:
            input_path: Path to the binary file
            run_auto_analysis: Whether to run auto-analysis
            session_id: Optional custom session ID (auto-generated if not provided)

        Returns:
            Session ID for the opened binary

        Raises:
            FileNotFoundError: If the input file doesn't exist
            RuntimeError: If failed to open the database
        """
        input_path = Path(input_path)

        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        with self._lock:
            # Check if this file is already tracked
            for sid, session in self._sessions.items():
                if session.input_path.resolve() == input_path.resolve():
                    logger.info(f"Binary already open in session: {sid}")
                    session.last_accessed = datetime.now()
                    return sid

            # Generate session ID
            if session_id is None:
                session_id = str(uuid.uuid4())[:8]
            elif session_id in self._sessions:
                raise ValueError(f"Session already exists: {session_id}")

            # Open the database
            logger.info(f"Opening database: {input_path} (session: {session_id})")
            self._activate_database_path(str(input_path), run_auto_analysis)

            # Create session object
            session = IDASession(
                session_id=session_id,
                input_path=input_path,
                is_analyzing=run_auto_analysis,
            )

            self._sessions[session_id] = session
            self._active_session_id = session_id

            # Wait for analysis if requested
            if run_auto_analysis:
                logger.debug(
                    f"Waiting for auto-analysis to complete (session: {session_id})"
                )
                ida_auto.auto_wait()
                session.is_analyzing = False
                logger.info(f"Auto-analysis completed (session: {session_id})")

            logger.info(f"Session created: {session_id} for {input_path.name}")
            return session_id

    def open_dsc(
        self,
        input_path: Path | str,
        module: str,
        idb_name: Optional[str] = None,
        dependency_depth: int = 0,
        run_auto_analysis: bool = True,
        session_id: Optional[str] = None,
    ) -> str:
        """Open a single module from a dyld shared cache file.

        The Mach-O loader uses environment variables to control DSC loading:
        - IDA_DYLD_CACHE_MODULE: module path for single-module mode
        - IDA_DYLD_CACHE_DEPTH: dependency loading depth (-1 = all)

        To produce a custom IDB filename (e.g. ``SwiftUI.i64``), a temporary
        symlink is created in the same directory as the cache so that IDA
        names the database after the symlink.  The symlink is removed once
        the database is open.

        Args:
            input_path: Path to the dyld shared cache file
            module: Module path to load (e.g. "/usr/lib/libobjc.A.dylib").
            idb_name: Custom base name for the .i64 file.  Defaults to the
                      module's file name (last path component).
            dependency_depth: Depth of dependency loading (0 = module only, -1 = all)
            run_auto_analysis: Whether to run auto-analysis
            session_id: Optional custom session ID (auto-generated if not provided)

        Returns:
            Session ID for the opened DSC

        Raises:
            FileNotFoundError: If the input file doesn't exist
            RuntimeError: If failed to open the database
        """
        input_path = Path(input_path)

        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        with self._lock:
            if session_id is None:
                session_id = str(uuid.uuid4())[:8]
            elif session_id in self._sessions:
                raise ValueError(f"Session already exists: {session_id}")

            # Resolve the base name for the IDB file
            if idb_name is None:
                # Derive from module path, e.g. ".../AppKit" -> "AppKit"
                idb_name = Path(module).name

            logger.info(
                "Opening DSC: %s (module=%s, idb=%s, depth=%d, session=%s)",
                input_path, module, idb_name, dependency_depth, session_id,
            )

            # Create a symlink in the cache directory so IDA names the IDB
            # after the symlink rather than the cache file.
            symlink_path: Optional[Path] = None
            effective_path = str(input_path)

            if idb_name != input_path.name:
                symlink_path = input_path.parent / idb_name
                if symlink_path.exists() or symlink_path.is_symlink():
                    # Reuse existing file/symlink
                    logger.debug("IDB name target already exists: %s", symlink_path)
                else:
                    symlink_path.symlink_to(input_path.name)
                    logger.debug("Created symlink: %s -> %s", symlink_path, input_path.name)
                effective_path = str(symlink_path)

            # Set loader environment variables, then restore after open_database.
            # NOTE: os.environ is process-global; the session manager lock
            # serialises DSC opens but other threads could observe these
            # values during the window.  This is acceptable because idalib
            # itself is single-threaded.
            saved_env: dict[str, Optional[str]] = {}
            try:
                saved_env["IDA_DYLD_CACHE_MODULE"] = os.environ.get(
                    "IDA_DYLD_CACHE_MODULE"
                )
                os.environ["IDA_DYLD_CACHE_MODULE"] = module

                saved_env["IDA_DYLD_CACHE_DEPTH"] = os.environ.get(
                    "IDA_DYLD_CACHE_DEPTH"
                )
                os.environ["IDA_DYLD_CACHE_DEPTH"] = str(dependency_depth)

                self._activate_database_path(
                    effective_path, run_auto_analysis=run_auto_analysis
                )
            finally:
                for key, old_value in saved_env.items():
                    if old_value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = old_value
                # NOTE: do NOT remove the symlink here.  The dscu plugin
                # uses ida_nalt.get_input_file_path() (which returns the
                # symlink path) throughout the session to read DSC data
                # during reload_file_ex.  Removing it breaks dsc_load_*.

            # Track the effective path (symlink target dir + idb_name) so
            # session switching can find the IDB later.
            tracked_path = Path(effective_path)

            session = IDASession(
                session_id=session_id,
                input_path=tracked_path,
                is_analyzing=run_auto_analysis,
                metadata={
                    "dsc_path": str(input_path),
                    "dsc_module": module,
                    "idb_name": idb_name,
                    "dependency_depth": dependency_depth,
                },
            )

            self._sessions[session_id] = session
            self._active_session_id = session_id

            if run_auto_analysis:
                logger.debug(
                    "Waiting for auto-analysis to complete (session: %s)", session_id
                )
                ida_auto.auto_wait()
                session.is_analyzing = False
                logger.info("Auto-analysis completed (session: %s)", session_id)

            logger.info(
                "DSC session created: %s for %s (module=%s)",
                session_id, idb_name, module,
            )
            return session_id

    def close_session(self, session_id: str) -> bool:
        """Close a specific session and its database

        Args:
            session_id: Session ID to close

        Returns:
            True if closed successfully, False if session not found
        """
        with self._lock:
            if session_id not in self._sessions:
                logger.warning(f"Session not found: {session_id}")
                return False

            session = self._sessions[session_id]
            logger.info(f"Closing session: {session_id} ({session.input_path.name})")

            # If this is the active in-process database, close it.
            if self._active_session_id == session_id:
                idapro.close_database()
                self._active_session_id = None

            # Clean up DSC symlink if this was a DSC session
            self._cleanup_dsc_symlink(session)

            # Remove session
            del self._sessions[session_id]
            self._unbind_session_everywhere_locked(session_id)
            logger.info(f"Session closed: {session_id}")
            return True

    def bind_context(
        self, context_id: str, session_id: str, activate: bool = False
    ) -> IDASession:
        """Bind a transport context to a session.

        Args:
            context_id: Transport-specific context identifier.
            session_id: IDA session ID to bind.
            activate: Whether to activate the bound session immediately.

        Returns:
            The bound session object.
        """
        with self._lock:
            if session_id not in self._sessions:
                raise ValueError(f"Session not found: {session_id}")

            self._context_bindings[context_id] = session_id
            session = self._sessions[session_id]
            session.last_accessed = datetime.now()
            logger.info("Bound context %s -> session %s", context_id, session_id)

            if activate:
                self._activate_session_locked(session_id)
            return session

    def unbind_context(self, context_id: str) -> bool:
        """Remove an existing context binding."""
        with self._lock:
            removed = self._context_bindings.pop(context_id, None)
            if removed is None:
                return False
            logger.info("Unbound context %s from session %s", context_id, removed)
            return True

    def get_context_session_id(self, context_id: str) -> Optional[str]:
        """Return the session ID bound to a context."""
        with self._lock:
            return self._context_bindings.get(context_id)

    def get_context_session(self, context_id: str) -> Optional[IDASession]:
        """Get the session object bound to a context."""
        with self._lock:
            session_id = self._context_bindings.get(context_id)
            if session_id is None:
                return None
            return self._sessions.get(session_id)

    def activate_context(self, context_id: str) -> IDASession:
        """Activate the database bound to a context for the current request."""
        with self._lock:
            session_id = self._context_bindings.get(context_id)
            if session_id is None:
                raise RuntimeError(
                    "No session bound for this context. "
                    "Use idalib_switch(session_id) or idalib_open(...) first."
                )
            session = self._sessions.get(session_id)
            if session is None:
                self._context_bindings.pop(context_id, None)
                raise RuntimeError(
                    f"Context binding is stale (missing session: {session_id}). "
                    "Bind to a valid session again."
                )

            self._activate_session_locked(session_id)
            session.last_accessed = datetime.now()
            return session

    def list_sessions(self, context_id: Optional[str] = None) -> list[dict]:
        """List all open sessions with binding and activation metadata."""
        with self._lock:
            context_session_id = self._context_bindings.get(context_id, None)
            binding_counts: Dict[str, int] = {}
            for bound_session_id in self._context_bindings.values():
                binding_counts[bound_session_id] = (
                    binding_counts.get(bound_session_id, 0) + 1
                )

            return [
                {
                    **session.to_dict(),
                    "is_active": session.session_id == self._active_session_id,
                    "is_current_context": session.session_id == context_session_id,
                    "bound_contexts": binding_counts.get(session.session_id, 0),
                }
                for session in self._sessions.values()
            ]

    def get_session(self, session_id: str) -> Optional[IDASession]:
        """Get a specific session by ID

        Args:
            session_id: Session ID to retrieve

        Returns:
            Session object or None if not found
        """
        with self._lock:
            return self._sessions.get(session_id)

    def close_all_sessions(self):
        """Close all sessions and databases"""
        with self._lock:
            logger.info(f"Closing all {len(self._sessions)} sessions")

            if self._active_session_id is not None:
                idapro.close_database()
                self._active_session_id = None

            for session in self._sessions.values():
                self._cleanup_dsc_symlink(session)
            self._sessions.clear()
            self._context_bindings.clear()
            logger.info("All sessions closed")

    def _activate_session_locked(self, session_id: str) -> None:
        if self._active_session_id == session_id:
            return
        session = self._sessions.get(session_id)
        if session is None:
            raise ValueError(f"Session not found: {session_id}")
        self._activate_database_path(str(session.input_path), run_auto_analysis=False)
        self._active_session_id = session_id
        logger.info("Activated session %s (%s)", session_id, session.input_path.name)

    def _activate_database_path(self, input_path: str, run_auto_analysis: bool) -> None:
        if self._active_session_id is not None:
            logger.debug("Closing active database before opening %s", input_path)
            idapro.close_database()
            self._active_session_id = None

        if idapro.open_database(input_path, run_auto_analysis=run_auto_analysis):
            raise RuntimeError(f"Failed to open database: {input_path}")

    @staticmethod
    def _cleanup_dsc_symlink(session: IDASession) -> None:
        """Remove the DSC symlink created by open_dsc, if any."""
        dsc_path = session.metadata.get("dsc_path")
        if not dsc_path:
            return
        # The symlink is input_path itself (e.g. .../AppKit -> dyld_shared_cache_arm64e)
        symlink = session.input_path
        if symlink.is_symlink():
            try:
                symlink.unlink()
                logger.debug("Removed DSC symlink: %s", symlink)
            except OSError:
                pass

    def _unbind_session_everywhere_locked(self, session_id: str) -> None:
        stale_contexts = [
            context_id
            for context_id, bound_session_id in self._context_bindings.items()
            if bound_session_id == session_id
        ]
        for context_id in stale_contexts:
            del self._context_bindings[context_id]


# Global session manager instance
_session_manager: Optional[IDASessionManager] = None


def get_session_manager() -> IDASessionManager:
    """Get the global session manager instance

    Returns:
        Global IDASessionManager instance
    """
    global _session_manager
    if _session_manager is None:
        _session_manager = IDASessionManager()
    return _session_manager
