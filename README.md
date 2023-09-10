
Delaying SURBs in Katzenpost
==============================

This is a proof of concept implementation of the "Delaying SURBs" attack. The majority of the source code is forked
form Katzenpost, as well as most of this guide. 

First follow the instructions to run Katzenpost:

This Podman-compatible docker-compose configuration is intended to allow
Katzenpost developers to locally run an offline test network on their
development system. It is meant for developing and testing client and server
mix network components as part of the core Katzenpost developer work flow.

0. Requirements

* Podman or Docker
* docker-compose (tested with 1.29.2, among other versions)
* GNU Make

1. Run a test network
```
   git clone git@github.com:Ti-ger/Benign-Katzenpost.git
   cd Benign-Katzenpost
   cd docker
   make run-voting-testnet
```
Note that if you do not have podman and your system configuration requires you
to ``sudo`` to use docker, you will need to prefix all of the ``make`` commands
in this directory with ``sudo``. If you have both podman and docker installed,
you can override the automatic choice of podman over docker by prefixing the
``make`` argument list with ``docker=docker``.

Also note that if you are using podman, you'll need to have the podman system
service running, and pointed to by DOCKER_HOST environment variable.

```
export DOCKER_HOST=unix:///var/run/user/$(id -u)/podman/podman.sock
podman system service -t 0 $DOCKER_HOST &
```

At this point, you should have a locally running network. You can hit ctrl-C to
stop it, or use another terminal to observe the logs with ``tail -F voting_mixnet/*/*log``.

2. You can now observe the status of the mix net
```
  make status
```
It will take a few minutes until the mix net has reached the first consensus.

Once the mix net has reached a consensus:
> 14:49:16.240 NOTI state: Consensus made for epoch 1650685 with 3/3 signatures

we can mount the attack.

3. We want to observe the logs of our corrupted providers, so open two new shells:
```
  Benign-Katzenpost/docker/voting_mixnet$ tail -f provider1/katzenpost.log | strings | grep maligne
  Benign-Katzenpost/docker/voting_mixnet$ tail -f provider2/katzenpost.log | strings | grep maligne
```

4. We will now use the catshadow test case to simulate users. Open yet another shell:

```
  Benign-Katzenpost/catshadow$ make dockerdockertest
```

You should now be able to observe that one provider is collecting SURBS:
> 14:52:58.074 DEBU maligne: Delaying pkt: 144  
 14:53:11.312 DEBU maligne: Witnessed victim: [145 41 30 234 86 168 151 49 232 146 236 110]  
 14:53:11.312 DEBU maligne: Delaying pkt: 160  
 14:53:26.304 DEBU maligne: Witnessed victim: [145 41 30 234 86 168 151 49 232 146 236 110]  
 14:53:26.304 DEBU maligne: Delaying pkt: 178  
 14:53:48.514 DEBU maligne: Witnessed victim: [145 41 30 234 86 168 151 49 232 146 236 110]  
14:53:48.515 DEBU maligne: Delaying pkt: 208  
14:53:55.000 DEBU maligne: Timer has fired!  
14:53:55.002 DEBU maligne: Attack Threshold reached! Collected 11 packets  
14:53:55.002 DEBU maligne: Sending Pkt: 60  
14:53:55.002 DEBU maligne: Sending Pkt: 72  
14:53:55.002 DEBU maligne: Sending Pkt: 82  
14:53:55.002 DEBU maligne: Sending Pkt: 90  
14:53:55.002 DEBU maligne: Sending Pkt: 100  
14:53:55.002 DEBU maligne: Sending Pkt: 120  
14:53:55.002 DEBU maligne: Sending Pkt: 128  
14:53:55.002 DEBU maligne: Sending Pkt: 144  
14:53:55.002 DEBU maligne: Sending Pkt: 160  
14:53:55.002 DEBU maligne: Sending Pkt: 178  
14:53:55.002 DEBU maligne: Sending Pkt: 208  
14:53:55.002 DEBU maligne: Mischief Managed  

While the other provider witnesses the attack:
> 14:53:55.264 DEBU maligne: Attack was successful, victim is: [199 232 52 23 67 2 203 50 32 16 149 64 198 55 0 212 124 126 217 99 130 244 94 137 55 52 107 151 90 227 14 131]  
14:53:55.264 DEBU maligne: Mischief Managed

Note, depending on when you start the attack it might take another epoch to collect enough SURBs.

This code is currently uses shorter epochs, but you can run this test also with the usual amount of 20 minutes, by using the parameter "warped=false"
```
  make run voting_mixnet warped=false
  make dockerdockertest warped=fals
```
