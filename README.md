# RFID Doorlock Backend (file-based logging)

No database — users are stored in `data/users.json`, and events are appended as
JSON lines to `logs/access.log` and `logs/intrusion.log`.

## Run

```bash
npm install
npm start
```

Server listens on port 3000 by default (set `PORT` env var to change).

## Endpoints

| Method | Route                  | Body                          | Purpose                        |
|--------|-------------------------|--------------------------------|---------------------------------|
| POST   | /api/auth               | `{ "uid": "A1B2C3D4" }`        | Check UID, logs to access.log  |
| POST   | /api/users               | `{ "uid": "...", "name": "John" }` | Register new UID (admin enroll) |
| GET    | /api/users               | -                               | List registered users          |
| DELETE | /api/users/:uid          | -                               | Remove a user                  |
| POST   | /api/intrusion            | `{ "sensor": "vibration" }`    | Log break-in event             |
| GET    | /api/logs/access?limit=50 | -                             | Recent access attempts         |
| GET    | /api/logs/intrusion?limit=50 | -                          | Recent intrusion events        |

## Example: STM32 -> ESP-01S -> Server (raw HTTP over AT commands)

Point the ESP-01S at your machine's LAN IP, e.g. `192.168.1.50:3000`.

Raw HTTP request the STM32 should send through the ESP-01S TCP connection:

```
POST /api/auth HTTP/1.1
Host: 192.168.1.50:3000
Content-Type: application/json
Content-Length: 20
Connection: close

{"uid":"A1B2C3D4"}
```

Response body will be JSON like:
```json
{"granted":true,"name":"John"}
```

Same pattern applies for `/api/intrusion` and `/api/users`, just change the
path and JSON body.

## Notes
- `users.json` and the log files are plain text — easy to inspect, back up, or
  swap into a real DB later without changing the API surface.
- If you outgrow file logging (many devices, concurrent writes), migrate to
  SQLite/Postgres later — the route handlers are the only thing that would
  need to change.
