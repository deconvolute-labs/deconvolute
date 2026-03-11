import typing
from typing import Any

import httpcore

from deconvolute.errors import PinnedConnectionError


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """
    A custom network backend for secure DNS pinning with fallback support.

    This backend intercepts TCP connection requests. If the requested host matches
    the target original_host, it routes the socket to a list of resolved IPs. It
    tries them sequentially, falling back on failure. Once an IP successfully connects,
    it locks onto that IP for all future connections to ensure zero latency overhead.
    It delegates the TLS handshake to the original host string to preserve SNI.
    """

    def __init__(
        self,
        original_host: str,
        pinned_ips: list[str],
        backend: httpcore.AsyncNetworkBackend,
    ) -> None:
        """
        Initializes the PinnedNetworkBackend.

        Args:
            original_host (str): The target hostname to intercept
                (e.g. 'api.example.com').
            pinned_ips (list[str]): The resolved IP addresses to try connecting to.
            backend (httpcore.AsyncNetworkBackend): The underlying httpcore backend
                to wrap.
        """
        self._original_host = original_host
        self._pinned_ips = pinned_ips
        self._backend = backend
        self._locked_ip: str | None = None

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[
            tuple[int, int, int]
            | tuple[int, int, bytes | bytearray]
            | tuple[int, int, None, int]
        ]
        | None = None,
        **kwargs: Any,
    ) -> httpcore.AsyncNetworkStream:
        """
        Intercepts and routes TCP connections to the pinned IP if the host matches.

        Args:
            host (str): The hostname requested by the client.
            port (int): The destination port.
            timeout (float | None, optional): The connection timeout in seconds.
                Defaults to None.
            local_address (str | None, optional): The local address to bind to.
                Defaults to None.
            **kwargs (Any): Additional keyword arguments passed to the backend.

        Returns:
            httpcore.AsyncNetworkStream: The established TCP stream.
        """
        # If it is not our target host, pass it through normally
        if host != self._original_host:
            return await self._backend.connect_tcp(
                host=host,
                port=port,
                timeout=timeout,
                local_address=local_address,
                socket_options=socket_options,
                **kwargs,
            )

        # Fast path: If we already found a working IP, use it immediately
        if self._locked_ip:
            return await self._backend.connect_tcp(
                host=self._locked_ip,
                port=port,
                timeout=timeout,
                local_address=local_address,
                socket_options=socket_options,
                **kwargs,
            )

        # Fallback path: Try IPs sequentially until one connects
        last_exception: Exception | None = None

        for ip in self._pinned_ips:
            try:
                stream = await self._backend.connect_tcp(
                    host=ip,
                    port=port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                    **kwargs,
                )
                # Success. Lock this IP for all future connections.
                self._locked_ip = ip
                return stream
            except Exception as error:
                # Connection failed (e.g. broken IPv6 route). Save error and try next.
                last_exception = error
                continue

        # If all IPs fail, raise final exception
        if last_exception:
            raise PinnedConnectionError(
                f"Deconvolute Firewall: Failed to connect to any pinned IPs for "
                f"{self._original_host}. Underlying error: {last_exception}"
            ) from last_exception

        raise PinnedConnectionError(
            f"No valid IP addresses provided for {self._original_host}"
        )

    async def connect_unix_socket(
        self, *args: Any, **kwargs: Any
    ) -> httpcore.AsyncNetworkStream:
        """
        Delegates UNIX socket connections to the underlying backend.

        Args:
            *args (Any): Positional arguments.
            **kwargs (Any): Keyword arguments.

        Returns:
            httpcore.AsyncNetworkStream: The established UNIX socket stream.
        """
        return await self._backend.connect_unix_socket(*args, **kwargs)

    async def sleep(self, seconds: float) -> None:
        """
        Delegates sleep calls to the underlying backend.

        Args:
            seconds (float): The duration to sleep in seconds.
        """
        return await self._backend.sleep(seconds)
