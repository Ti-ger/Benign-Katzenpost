warped?=true
CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f"
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"
uid=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)
distro=alpine
image=katzenpost-$(distro)_go_mod
docker_args=--user ${docker_user} -v $(shell readlink -f ..):/go/katzenpost -e GOCACHE=/tmp/gocache --network=host --rm

test:
	CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go test -v -race -timeout 0 -ldflags ${ldflags} .

lint:
	golint ./...

coverage-file:
	CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go test ./... -coverprofile=coverage.out

coverage-html:
	CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go tool cover -html=coverage.out


dockerdockertest:
	$(docker) run ${docker_args} $(image) \
		sh -c 'cd /go/katzenpost/client/; GORACE=history_size=7 CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go test $(testargs) -ldflags ${ldflags} -tags=docker_test -race -v -timeout 1h -run Docker'
