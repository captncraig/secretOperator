
docker run -it --rm -v d:/gopath/src/github.com/captncraig/secretOperator:/go/src/github.com/captncraig/secretOperator \
--workdir="//go/src/github.com/captncraig/secretOperator"  golang:1.10 \
bash hack/update-codegen.sh