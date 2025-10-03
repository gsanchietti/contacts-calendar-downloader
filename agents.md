# Istruzioni per l'Agente: Script Python per Download Contatti Google in CSV

**Obiettivo:** Creare uno script Python completo che si connetta alla Google People API per scaricare tutti i contatti dell'utente autenticato e salvarli in un file CSV.

**Prerequisiti e Setup (Da Comunicare all'Utente):**

1.  **Abilitazione API:** L'utente deve abilitare la **Google People API** nella Google Cloud Console e creare le credenziali **OAuth 2.0** (tipo 'Desktop app' o 'Applicazione web', a seconda del contesto di esecuzione) per ottenere il file `credentials.json`.
2.  **Librerie Python:** Lo script richiederà l'installazione delle seguenti librerie:
    ```bash
    pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib
    ```

**Struttura dello Script (`download_google_contacts.py`):**

1.  **Importazioni:** Importare le librerie necessarie (`os`, `pickle`, `csv`, `googleapiclient.discovery`, `google_auth_oauthlib.flow`, `google.auth.transport.requests`).
2.  **Configurazione:**
    * Definire lo **SCOPE** necessario: `https://www.googleapis.com/auth/contacts.readonly` (o `https://www.googleapis.com/auth/contacts` se sono necessarie anche operazioni di scrittura).
    * Definire il nome del file **JSON delle credenziali** (es. `credentials.json`) e il nome del file per il **token di autenticazione** (es. `token.pickle`).
    * Definire il nome del file **CSV di output** (es. `google_contacts.csv`).
3.  **Funzione di Autenticazione (`authenticate_google()`):**
    * Implementare il flusso di autenticazione **OAuth 2.0**.
    * Controllare se esiste un file `token.pickle` per riutilizzare le credenziali.
    * Se il token non è valido o inesistente, avviare il flusso di autorizzazione **senza** l'utilizzo del browser, ma tutto da linea di comand
    * Salvare il nuovo token in `token.pickle`.
    * Restituire l'oggetto `service` costruito per l'API People (`people`, versione `v1`).
4.  **Funzione di Download dei Contatti (`download_contacts(service)`):**
    * Utilizzare il metodo `service.connections().list()` per ottenere i contatti.
    * Utilizzare `resourceName='people/me'` per i propri contatti.
    * Specificare i **campi (fields) da recuperare** con `personFields`. I campi minimi dovrebbero essere: `names`, `emailAddresses`, `phoneNumbers`. *Nota: Si dovranno considerare tutti i campi utili come `organizations`, `addresses`, `birthdays`, ecc.*
    * Gestire la **paginazione** utilizzando `pageToken` per scaricare tutti i contatti (l'API People limita i risultati per chiamata).
    * Restituire una lista di oggetti contatto.
5.  **Funzione di Scrittura CSV (`write_to_csv(contacts, filename)`):**
    * Definire un **elenco di intestazioni CSV** che mappino i dati JSON della API a colonne CSV leggibili (es. `Nome Completo`, `Email Principale`, `Telefono Lavoro`, `Telefono Cellulare`, ecc.).
    * Iterare sulla lista dei contatti.
    * Per ogni contatto, estrarre i dati in modo **sicuro** (gestendo i casi in cui un campo sia assente, es. con `.get()` e controlli sulla lista).
    * Scrivere i dati nel file CSV specificato.
6.  **Funzione Principale (`main()`):**
    * Chiamare `authenticate_google()`.
    * Chiamare `download_contacts(service)`.
    * Chiamare `write_to_csv(contacts, google_contacts.csv)`.
    * Aggiungere un messaggio di conferma per l'utente.

**Output Desiderato:**

* Un file Python funzionante: `download_google_contacts.py`.
* Un'intestazione chiara che elenchi i campi principali estratti (`Nome`, `Email`, `Telefono`).
* Gestione della paginazione e dei dati opzionali/mancanti.
