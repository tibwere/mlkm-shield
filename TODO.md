# Idee per sviluppi futuri

* Esecuzione single-step (debug mode) per analizzare le singole istruzioni macchina da eseguire al fine di intercettare possibili pattern malevoli (e.g. sovrascrittura di `cr0`)
* Integrity checker _globale_ basato su regole comportamentali (e.g. passaggio di parametri _insoliti_ ad alcune system call per accedere a determinati servizi)
* Estensione del controllo anche a rootkit user-space
* Utilizzo del memory management per controllare a grana fine il comportamento dei moduli montati (e.g. forzare un fault quando si accede alle pagine di memoria in cui è presente il codice macchina del modulo
* Spawn di $N-1$ thread a priorità massima, utilizzando FIFO scheduling, per _occupare_ le altre CPU mentre è in esecuzione un modulo monitorato
* Calcolare l'hash del codice macchina delle system call per evitare l'_hot patching_
