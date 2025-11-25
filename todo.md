WebHashcat (Utils/tasks):

_task_with_lock unifica già lock+log; può essere esteso a refresh_node_cache_task per includere cleanup log (se serve messaggistica) e a eventuali nuovi job, magari aggiungendo un parametro opzionale per loggare inizio/fine con logger.

quando aggiungo una nuova sessione una volta che ho caricato il/gli hash, la tabella è dapprima vuota con Node data unavailable
Node				Node data unavailable	
poi dopo anche 60 secondi si popola. 
Node	dictionary		Arab_[Name]	Not started	N/A	0 %	N/A	
come mai?

come profili docker per il nodo hashcat abbiamo cuda, intel-cpu e pocl
aggiungi [amd-gpu, intel-gpu] come da documentazione di dizcza/docker-hashcat "with hashcat utils on Ubuntu 18.04 for Nvidia GPUs (:cuda), AMD GPUs (:latest), Intel GPUs (:intel-gpu), Intel CPUs (:intel-cpu), KVMs and AMD CPUs (:pocl)"<

la dashboard non sta funzionando: non vedo i nodi (ne ho 1), non vedo gli hash o statistiche, non vedo le sessioni (1 attiva)
cerca di sistemarla o reworkarla in modo intelligente. voglio vedere i nodi, se stanno lavorando, voglio vedere le sessioni in corso, la statistica del lavoro fatto, hash craccati, ecc..