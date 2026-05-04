# Guía de Publicación y Uso del Repositorio

## 1. Requisitos Previos

- **Python 3.8+** instalado
- **Git** instalado y configurado
- Cuenta en **GitHub**
- Librería **rdflib** instalada

### Instalar dependencias

```bash
pip install rdflib
```

## 2. Clonar el Repositorio

```bash
git clone https://github.com/danielpegat/ontologia-ciberseguridad.git
cd ontologia-ciberseguridad
```

## 3. Estructura del Proyecto

```
ontologia-ciberseguridad/
├── README.md                       # Descripción del proyecto
├── ontologia.owl                   # Ontología OWL/RDF
├── ejemplos/
│   ├── consultas_sparql.md         # Consultas SPARQL de ejemplo
│   └── agente_python.py            # Agente inteligente
└── docs/
    └── guia_publicacion.md         # Esta guía
```

## 4. Ejecutar el Agente

Desde la raíz del repositorio:

```bash
python ejemplos/agente_python.py
```

El agente realizará los siguientes pasos automáticamente:

1. **Carga** la ontología `ontologia.owl`
2. **Explora** las clases, individuos y relaciones
3. **Analiza** amenazas, niveles de riesgo y criticidad de activos
4. **Genera recomendaciones** de seguridad basadas en las reglas del agente

## 5. Modificar la Ontología

Para editar la ontología:

1. Abre `ontologia.owl` en **Protégé 5.6.9**
2. Realiza tus modificaciones (agregar clases, individuos, relaciones)
3. Guarda el archivo en formato **RDF/XML**
4. Vuelve a ejecutar el agente para ver las nuevas recomendaciones

## 6. Publicar Cambios en GitHub

```bash
git add .
git commit -m "Descripción de los cambios realizados"
git push origin main
```

## 7. Conceptos Clave

### ¿Qué es un agente?

Un **agente** es una entidad de software que percibe su entorno a través de sensores y actúa sobre él mediante actuadores. En inteligencia artificial, un agente es un programa capaz de tomar decisiones autónomas para alcanzar un objetivo, basándose en la información que percibe del entorno.

Características principales:
- **Autonomía**: Opera sin intervención directa del usuario
- **Reactividad**: Responde a cambios en su entorno
- **Proactividad**: Toma iniciativa para alcanzar sus objetivos
- **Sociabilidad**: Puede interactuar con otros agentes

### Clasificación de los agentes

| Tipo | Descripción | Ejemplo |
|------|-------------|---------|
| **Agente reactivo simple** | Actúa según reglas condición-acción directas | Termostato |
| **Agente reactivo basado en modelo** | Mantiene un estado interno del mundo | Robot con mapa |
| **Agente basado en objetivos** | Busca alcanzar metas específicas | GPS/navegador |
| **Agente basado en utilidad** | Maximiza una función de utilidad | Sistema de inversiones |
| **Agente que aprende** | Mejora su comportamiento con la experiencia | Filtro de spam |

### Nuestro agente

El agente desarrollado en este proyecto es un **agente reactivo basado en modelo**, ya que:

- Mantiene un **modelo interno** del dominio (la ontología OWL/RDF)
- **Percibe** el estado de la ontología (amenazas, riesgos, controles)
- **Razona** sobre la base de conocimiento usando reglas predefinidas
- **Actúa** emitiendo recomendaciones de seguridad

## 8. Referencias

- [Protégé](https://protege.stanford.edu/) — Editor de ontologías
- [rdflib Documentation](https://rdflib.readthedocs.io/) — Librería RDF para Python
- [OWL Web Ontology Language](https://www.w3.org/OWL/) — Estándar W3C
- Russell, S. & Norvig, P. (2020). *Artificial Intelligence: A Modern Approach*. 4th Edition.
