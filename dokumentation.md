# Server
> Port: _8787_
> 
> Message to disconnect: _!DISCONNECT_
> 
> Message Length: _1024 (utf-8 encoded)_
***

### _start()_
> Keine Parameter
- Server wird gestartet
- So lange der Boolean _server_running_ auf _true_ gesetzt ist:
  - Werden neue Verbindungen zugelassen. Gespeichert wird: _Connection_ und _Adresse_ (Nutzlos)
  - Für jede Verbindung (Client) wird ein neuer Thread (mit der _handle_client_ Funktion) erstellt.
- Bei einem _KeyboardInterrupt_ wird die Funktion _disconnect_all()_ ausgeführt und der server runtergefahren, bevor das Programm terminiert.
***

### _handle_client()_
> Parameter: _connection_ des Clients.
- Empfängt eine init-Nachricht, welche der Authentifizierung dient. Format => request (login/Create User), username, password
  - Entweder versucht der Client sich anzumelden


***
***
# Client


***
***
# Begriffe & Variablen
- Verbindung: _Identifiziert den Client. Wir u.a. gebraucht um Nachrichten an diesen zurückzuschicken._