# Consultas SPARQL

## Consultar controles que mitigan una amenaza

```sparql
SELECT ?control WHERE {
    <http://www.miOntologia.org/ciberseguridad#Phishing>
    <http://www.miOntologia.org/ciberseguridad#mitiga> ?control .
}
```

## Consultar todas las amenazas

```sparql
PREFIX cib: <http://www.miOntologia.org/ciberseguridad#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?amenaza
WHERE {
    ?amenaza rdfs:subClassOf cib:Amenaza .
}
```

## Consultar todas las relaciones de mitigación

```sparql
PREFIX cib: <http://www.miOntologia.org/ciberseguridad#>

SELECT ?control ?amenaza
WHERE {
    ?control cib:Mitiga ?amenaza .
}
```
