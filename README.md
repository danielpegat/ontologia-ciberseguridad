# 🔐 Ontología de Ciberseguridad

Ontología OWL/RDF que modela los conceptos fundamentales de la ciberseguridad: amenazas, vulnerabilidades, controles de seguridad, activos y políticas. Incluye un agente inteligente en Python que consulta la ontología para emitir recomendaciones de seguridad.

## 📁 Estructura del Repositorio

```
ontologia-ciberseguridad/
├── README.md                       # Este archivo
├── ontologia.owl                   # Ontología OWL/RDF (Protégé)
├── ejemplos/
│   ├── consultas_sparql.md         # Consultas SPARQL de ejemplo
│   └── agente_python.py            # Agente inteligente en Python
└── docs/
    └── guia_publicacion.md         # Guía de publicación y uso
```

## 🧠 Descripción de la Ontología

La ontología modela el dominio de la ciberseguridad con las siguientes clases principales:

| Clase | Descripción |
|-------|-------------|
| **Amenaza** | Eventos que pueden comprometer la seguridad (Malware, Phishing, Spyware) |
| **Vulnerabilidad** | Debilidades explotables (Software desactualizado, Contraseñas débiles, Configuración incorrecta) |
| **Control** | Mecanismos de protección (Firewall, Antivirus, Encriptación, Autenticación Doble Factor) |
| **Activo** | Recursos a proteger (Servidor, Base de datos, Aplicación Web) |
| **Política** | Normas y reglas de seguridad (Política de Acceso, de Contraseñas, de Seguridad) |

### Relaciones (Object Properties)

- **Afecta**: Una Amenaza afecta a un Activo
- **Mitiga**: Un Control mitiga una Amenaza
- **Requiere**: Una Política requiere un Control

### Propiedades de Datos (Data Properties)

- `nivelRiesgo` (integer): Nivel de riesgo de una amenaza
- `criticidad` (integer): Nivel de criticidad de un activo
- `fechaDetección` (dateTime): Fecha de detección

## 🤖 Agente Inteligente

El agente en Python (`ejemplos/agente_python.py`) utiliza la librería `rdflib` para:

1. Cargar y parsear la ontología OWL/RDF
2. Consultar las clases, individuos y relaciones
3. Analizar amenazas detectadas y su nivel de riesgo
4. **Recomendar controles de seguridad** según las amenazas encontradas

### Requisitos

```bash
pip install rdflib
```

### Ejecución

```bash
python ejemplos/agente_python.py
```

## 🛠️ Herramientas Utilizadas

- [Protégé 5.6.9](https://protege.stanford.edu/) — Editor de ontologías
- [Python 3](https://www.python.org/) — Lenguaje del agente
- [rdflib](https://rdflib.readthedocs.io/) — Librería para manipulación de grafos RDF

## 👤 Autor

**Luis Daniel Peña Gaytán**  
Ingeniería en Sistemas Computacionales  
Actividad 9 — Agente basado en ontología
