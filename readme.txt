curl -X POST 'localhost:8888/route/set?var=$dynamic&backend=backends2@app3&api=/1111'
curl -X DELETE 'localhost:8888/route/delete?var=$dynamic&backend=backends2@app3&api=/1111'


curl -X DELETE "localhost:6000/upstream/delete?name=test1"