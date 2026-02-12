# TODO

## Connection Reconnect Handling
- Option A: Enable TCP keepalive + reasonable idle timeout
  - SetKeepAlive(true) and SetKeepAlivePeriod(1–5m).
  - Keep DisconnectTimeout at 1h; keepalive should detect dead peers earlier.
- Option B: Allow reconnect by kicking old session on login
  - Track active connections by client hash/ID.
  - On new login, close old conn and call Storage.Disconnect(old).
- Option C: Dual strategy
  - Keepalive + kick old session on login for fastest recovery.
