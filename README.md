# Ontología de Ciberseguridad

## Descripción de la ontología
Esta ontología (en formato OWL/RDF) modela los conceptos fundamentales del dominio de la ciberseguridad. Define las clases principales como Amenaza, Control y Activo, junto con sus relaciones (por ejemplo, `mitiga` y `afecta`). Además, contiene individuos específicos como Phishing, Malware, Firewall, y Autenticación Doble Factor, sirviendo como una base de conocimiento estructurada para sistemas de razonamiento y agentes inteligentes.

## Ejemplos de uso (consultas SPARQL)

Consultar todas las amenazas:
```sparql
PREFIX cib: <http://www.miOntologia.org/ciberseguridad#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?amenaza
WHERE {
    ?amenaza rdfs:subClassOf cib:Amenaza .
}
```

Consultar todas las relaciones (qué controles mitigan qué amenazas):
```sparql
PREFIX cib: <http://www.miOntologia.org/ciberseguridad#>

SELECT ?control ?amenaza
WHERE {
    ?control cib:Mitiga ?amenaza .
}
```

Consultar los controles que mitigan el Phishing:
```sparql
SELECT ?control WHERE {
    <http://www.miOntologia.org/ciberseguridad#Phishing>
    <http://www.miOntologia.org/ciberseguridad#mitiga> ?control .
}
```

## Namespace definido
http://www.miOntologia.org/ciberseguridad#
