open declarations

//store response
run test_store{
	#HTTPClient = 1
	#HTTPServer = 1

	#HTTPRequest = 1
	#HTTPResponse = 1

	some CacheState.dif.store
} for 2

//store two responses at the same time
run test_store2{
	#NetworkEndpoint = 2
	#HTTPClient = 1
	#HTTPServer = 1

	#HTTPRequest = 2
	#HTTPResponse = 2

	some cs:CacheState | #(cs.dif.store) = 2
} for 4

//test reusing
run test_reuse{
	#HTTPClient = 1
	#HTTPServer = 1
	#Cache = 1

	#HTTPRequest = 2
	#HTTPResponse = 1
	#CacheReuse = 1
} for 4

//test verification
run test_verification{
	#HTTPClient = 1
	#HTTPServer = 1
	#HTTPIntermediary = 0
	#Cache = 1
	#PrivateCache = 1

	some str:StateTransaction | checkVerification[str]
} for 6

//check "private" option
//It works when "No instance found" 
run checkPrivateOption{
	all c:Cache | c in PublicCache
	some CacheState.dif.store
	all res:HTTPResponse | one op:Private | op in res.headers.options
}

//check "no-store" option
//It works when "No instance found" 
run checkNoStoreOption{
	some CacheState.dif.store
	all res:HTTPResponse | one op:NoStore | op in res.headers.options
}

//check "no-cache" option 
//It works when "No instance found" 
run checkNoCacheOption{
	some str:StateTransaction |
	{
		some op:NoCache | op in str.request.headers.options
		one str.re_res
	}

	no str:StateTransaction | checkVerification[str]
}

//Same-orgin BCP Attack
run Same_origin_BCP{
	#HTTPClient = 1
	#HTTPServer = 1
	#HTTPIntermediary = 1
	#PrivateCache = 1
	#PublicCache = 0

	#HTTPRequest = 3
	#HTTPResponse = 2
	#CacheReuse = 1

	#Principal = 3
	#Alice = 2

	some tr,tr',tr'':HTTPTransaction | {
		//tr.req => tr'.req => tr'.res => tr.res => tr''.req => tr''.reuse
		tr'.request.current in tr.request.current.*next
		tr.response.current in tr'.response.current.*next
		tr''.request.current in tr.response.current.*next
		some tr''.re_res

		//tr: client <-> intermediary
		tr.request.from in HTTPClient
		tr.request.to in HTTPIntermediary

		//tr': intermediary <-> server
		tr'.request.from in HTTPIntermediary
		tr'.request.to in HTTPServer

		//tr'': client <-> ?
		tr''.request.from in HTTPClient

		tr.response.body != tr'.response.body
	}

	some c:HTTPClient | c in Alice.httpClients
	some s:HTTPServer | s in Alice.servers
	no i:HTTPIntermediary | i in Alice.servers
} for 6

//Cross-origin BCP Attack
run Cross_origin_BCP{
	#HTTPRequest = 5
	#HTTPResponse = 4
	#CacheReuse = 1

	#Browser = 1
	#HTTPServer = 2
	#HTTPProxy = 1
	#Cache = 1

	#Principal = 4
	#Alice = 3

	one Uri

	//cache exists only one in a browser
	all c:Cache | c in Browser.cache

	//set principal, gadget owner
	all p:Principal |	// every user controls only one gadget
		one c:HTTPConformist |
			c in p.(servers + httpClients)
	all b:Browser | b in Alice.httpClients	//Srowser is Client of Alice
	all s:HTTPServer | s in Alice.servers	//Server is Server of Alice 

	//MITM's action
	all tr:HTTPTransaction |{
		tr.request.to in HTTPIntermediary implies{
			one tr':HTTPTransaction |{
				tr'.request.from in HTTPIntermediary
				tr'.request.to in HTTPServer

				//tr'.cause = tr

				//tr.req -> tr'.req -> tr'.res -> tr.res
				tr'.request.current = tr.request.current.next
				tr'.response.current = tr'.request.current.next
				tr.response.current = tr'.response.current.next
			}
		}
	}

	//tr1 client <-> proxy(Attacker)
	//tr2 proxy <-> server1
	//tr3 client <-> proxy
	//tr4 proxy <-> server2
	//tr5 client <-> server1 (or server2)

	one disj tr1,tr3:HTTPTransaction |{
		tr1.request.from in HTTPClient
		tr1.request.to in HTTPIntermediary
		tr3.request.from in HTTPClient
		tr3.request.to in HTTPIntermediary

		tr3.request.current in tr1.response.current.*next
		tr3.cause = tr1
	}

	some tr2,tr4:HTTPTransaction |{
		tr2.request.from in HTTPProxy
		tr2.request.to in HTTPServer
		tr4.request.from in HTTPProxy
		tr4.request.to in HTTPServer
		tr2.request.to != tr4.request.to
	}

	one tr5:HTTPTransaction |{
		tr5.request.from in HTTPClient
		tr5.request.to in HTTPServer
		one tr5.re_res

		all tr:HTTPTransaction | (one tr.response implies tr5.request.current in tr.response.current.*next)
	}

	//HTTPbody tampered by Attacker
	all tr,tr':HTTPTransaction |{
		{
			tr.request.from in HTTPClient
			tr.request.to in HTTPIntermediary
			tr'.request.from in HTTPIntermediary
			tr'.request.to in HTTPServer
		}implies{
			tr.response.body != tr'.response.body
		}
	}
} for 10

//Cross-origin BCP Attack (prepare)
//A process to browser cache poisoning
run Cross_origin_BCP_prepare{
	#HTTPRequest = 4
	#HTTPResponse = 4

	#Browser = 1
	#HTTPServer = 2
	#HTTPProxy = 1
	#Cache = 1

	#Principal = 4
	#Alice = 3

	one Uri

	//cache exists in browser
	all c:Cache | c in Browser.cache

	//set the owner of gadget
	all p:Principal |	//every user controls only one gadget
		one c:HTTPConformist |
			c in p.(servers + httpClients)
	all b:Browser | b in Alice.httpClients	//browser is a client of Alice
	all s:HTTPServer | s in Alice.servers	//Server is a server of Alice

	//Communication Event
	some disj tr1,tr2,tr3,tr4:HTTPTransaction |{
		//tr1 client <-> proxy(Attacker)
		tr1.request.from in HTTPClient
		tr1.request.to in HTTPProxy

		//tr2 proxy <-> server1
		tr2.request.from in HTTPProxy
		tr2.request.to in HTTPServer

		//tr3 client <-> proxy
		tr3.request.from in HTTPClient
		tr3.request.to in HTTPProxy

		//tr4 proxy <-> server2
		tr4.request.from in HTTPProxy
		tr4.request.to in HTTPServer
		tr4.request.to != tr2.request.to

		//Order of Transactions
		tr2.request.current in tr1.request.current.*next
		tr1.response.current in tr2.response.current.*next
		tr3.request.current in tr1.response.current.*next
		tr4.request.current in tr3.request.current.*next
		tr3.response.current in tr4.response.current.*next

		//tampered HTTPresponse by Attacker
		tr1.response.body != tr2.response.body
		tr3.response.body != tr4.response.body

		//tr1 causes tr3
		tr3.cause = tr1

		//store response in browser cache
		no tr2.afterState.dif.store
		one tr4.afterState.dif.store
	}
} for 8

//Cross Site Request Forgery
run CSRF{
	#HTTPRequest = 2
	#HTTPResponse = 2

	#HTTPClient = 1
	#HTTPServer = 2
	#HTTPIntermediary = 0

	#Principal = 3
	#Alice = 2

	all p:Principal |
		one c:HTTPConformist |
			c in p.(servers + httpClients)
	all b:Browser | b in Alice.httpClients

	one tr1,tr2:HTTPTransaction|{
		//Order of transactions
		tr2.request.current in tr1.response.current.*next

		//tr1 client <-> server1(Attacker's)
		//tr2 client <-> server2
		tr1.request.to !in Alice.servers
		tr2.request.to in Alice.servers

		//tr1 causes r2
		tr2.cause = tr1

		tr1.request.uri != tr2.request.uri
	}
} for 4

//Web Cache Deception Attack
run Web_Cache_Deception{
	#HTTPRequest = 3
	#HTTPResponse = 2
	#CacheReuse = 1

	#HTTPClient = 2
	#HTTPServer = 1
	#HTTPProxy = 1
	#Cache = 1

	#Principal = 4
	#Alice = 3

	all c:Cache | c in HTTPProxy.cache

	all p:Principal |
		one c:HTTPConformist |
			c in p.(servers + httpClients)
	all i:HTTPProxy | i in Alice.servers
	all s:HTTPServer | s in Alice.servers

	one tr1,tr2,tr3:HTTPTransaction |{
		//tr1 client1 <-> proxy
		tr1.request.from in Alice.httpClients
		tr1.request.to in HTTPProxy

		//tr2 proxy <-> server
		tr2.request.from in HTTPProxy
		tr2.request.to in HTTPServer

		//tr3 client2(Attacker's) <-> proxy
		(tr3.request.from !in Alice.httpClients and tr3.request.from in HTTPClient)
		tr3.request.to in HTTPProxy

		one tr3.re_res
	}
} for 6

run test_intermediary{
	#HTTPRequest = 2
	#HTTPResponse = 2

	#HTTPClient = 1
	#HTTPServer = 1
	#HTTPIntermediary = 1

	//internediary is owned by Alice
	all i:HTTPIntermediary | i in Alice.servers

	one req:HTTPRequest | req.to in HTTPIntermediary
	one req:HTTPRequest | req.to in HTTPServer
} for 4
