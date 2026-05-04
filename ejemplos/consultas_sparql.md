# Consultas SPARQL para la Ontología de Ciberseguridad

A continuación se presentan consultas SPARQL que pueden ejecutarse sobre la ontología para extraer información relevante.

## 1. Listar todas las clases de la ontología

```sparql
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT ?clase
WHERE {
  ?clase rdf:type owl:Class .
}
```

## 2. Obtener todas las amenazas definidas

```sparql
PREFIX cib: <http://www.miOntologia.org/ciberseguridad#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?amenaza
WHERE {
  ?amenaza rdfs:subClassOf cib:Amenaza .
}
```

## 3. Listar todos los individuos (instancias) y su tipo

```sparql
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT ?individuo ?tipo
WHERE {
  ?individuo rdf:type owl:NamedIndividual .
  ?individuo rdf:type ?tipo .
  FILTER (?tipo != owl:NamedIndividual)
}
```

## 4. Consultar qué controles mitigan qué amenazas

```sparql
PREFIX cib: <http://www.miOntologia.org/ciberseguridad#>

SELECT ?control ?amenaza
WHERE {
  ?control cib:Mitiga ?amenaza .
}
```

## 5. Obtener activos con su nivel de criticidad

```sparql
PREFIX cib: <http://www.miOntologia.org/ciberseguridad#>

SELECT ?activo ?criticidad
WHERE {
  ?activo rdf:type cib:Activo .
  ?activo cib:criticidad ?criticidad .
}
```

## 6. Amenazas con nivel de riesgo alto (>= 4)

```sparql
PREFIX cib: <http://www.miOntologia.org/ciberseguridad#>

SELECT ?amenaza ?nivel
WHERE {
  ?amenaza cib:nivelRiesgo ?nivel .
  FILTER (?nivel >= 4)
}
```

## Nota

Estas consultas pueden probarse directamente con `rdflib` en Python usando el método `graph.query()` o en herramientas como Protégé (pestaña SPARQL Query).
