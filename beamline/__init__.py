"""Beamline: physically-sourced randomness with a publicly verifiable beacon."""

__version__ = "1.0.0"

#: Sent on every outbound request. Identifies the client to the services Beamline
#: depends on, so operators there can see who is polling them and get in touch.
USER_AGENT = f"beamline/{__version__}"

__all__ = ["__version__", "USER_AGENT"]
