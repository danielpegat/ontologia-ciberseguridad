"""
Agente Inteligente de Ciberseguridad
=====================================
Agente reactivo basado en la ontologia OWL/RDF de ciberseguridad.
Carga la ontologia, analiza amenazas, vulnerabilidades y controles,
y emite recomendaciones de seguridad personalizadas.

Autor: Luis Daniel Pena Gaytan
Materia: Ingenieria en Sistemas Basados en Conocimiento
"""

import sys
import io
import os

# Forzar codificacion UTF-8 en la salida para que los emojis se muestren correctamente
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from rdflib import Graph, Namespace, RDF, URIRef

# --- Configuracion -------------------------------------------------------

# Namespace de la ontologia
CIB = Namespace("http://www.miOntologia.org/ciberseguridad#")
OWL = Namespace("http://www.w3.org/2002/07/owl#")
RDFS = Namespace("http://www.w3.org/2000/01/rdf-schema#")

# Ruta al archivo de la ontologia (relativa al script)
RUTA_ONTOLOGIA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ontologia.owl")


# --- Funciones del Agente -------------------------------------------------

def cargar_ontologia(ruta):
    """Carga la ontologia OWL/RDF en un grafo RDF."""
    g = Graph()
    g.parse(ruta, format="xml")
    print(">> Ontologia cargada exitosamente.")
    print("   Tripletas totales: {}".format(len(g)))
    return g


def obtener_nombre(uri):
    """Extrae el nombre legible de una URI (lo que esta despues de #)."""
    if "#" in str(uri):
        return str(uri).split("#")[-1].replace("_", " ")
    return str(uri).split("/")[-1].replace("_", " ")


def listar_clases(g):
    """Lista todas las clases definidas en la ontologia."""
    clases = []
    for s in g.subjects(RDF.type, OWL.Class):
        nombre = obtener_nombre(s)
        if nombre:
            clases.append(nombre)
    return sorted(clases)


def listar_individuos(g):
    """Lista todos los individuos agrupados por su clase."""
    individuos = {}
    for s in g.subjects(RDF.type, OWL.NamedIndividual):
        nombre_individuo = obtener_nombre(s)
        for tipo in g.objects(s, RDF.type):
            nombre_tipo = obtener_nombre(tipo)
            if nombre_tipo != "NamedIndividual":
                if nombre_tipo not in individuos:
                    individuos[nombre_tipo] = []
                individuos[nombre_tipo].append(nombre_individuo)
    return individuos


def obtener_amenazas(g):
    """Obtiene todas las subclases de Amenaza."""
    amenazas = []
    for s in g.subjects(URIRef("http://www.w3.org/2000/01/rdf-schema#subClassOf"), CIB.Amenaza):
        amenazas.append(obtener_nombre(s))
    return amenazas


def obtener_controles(g):
    """Obtiene todas las subclases de Control."""
    controles = []
    for s in g.subjects(URIRef("http://www.w3.org/2000/01/rdf-schema#subClassOf"), CIB.Control):
        controles.append(obtener_nombre(s))
    return controles


def obtener_vulnerabilidades(g):
    """Obtiene todas las subclases de Vulnerabilidad."""
    vulnerabilidades = []
    for s in g.subjects(URIRef("http://www.w3.org/2000/01/rdf-schema#subClassOf"), CIB.Vulnerabilidad):
        vulnerabilidades.append(obtener_nombre(s))
    return vulnerabilidades


def obtener_mitigaciones(g):
    """Obtiene las relaciones de mitigacion (Control -> Amenaza)."""
    mitigaciones = []
    for s, o in g.subject_objects(CIB.Mitiga):
        mitigaciones.append((obtener_nombre(s), obtener_nombre(o)))
    return mitigaciones


def obtener_nivel_riesgo(g):
    """Obtiene individuos que tienen un nivel de riesgo asignado."""
    riesgos = []
    for s, o in g.subject_objects(CIB.nivelRiesgo):
        riesgos.append((obtener_nombre(s), int(o)))
    return riesgos


def obtener_criticidad(g):
    """Obtiene individuos que tienen criticidad asignada."""
    criticos = []
    for s, o in g.subject_objects(CIB.criticidad):
        criticos.append((obtener_nombre(s), int(o)))
    return criticos


# --- Base de Conocimiento del Agente --------------------------------------

# Reglas de recomendacion: para cada amenaza, que controles se recomiendan
REGLAS_RECOMENDACION = {
    "Phishing": [
        "Implementar Autenticacion de Doble Factor (2FA) en todas las cuentas",
        "Capacitar al personal en identificacion de correos fraudulentos",
        "Configurar filtros anti-phishing en el servidor de correo",
        "Establecer una Politica de Contrasenas robusta"
    ],
    "Malware": [
        "Instalar y mantener actualizado un Antivirus en todos los equipos",
        "Implementar un Firewall perimetral",
        "Mantener todo el software actualizado con los ultimos parches",
        "Restringir permisos de instalacion de software"
    ],
    "Spyware": [
        "Instalar herramientas anti-spyware especializadas",
        "Aplicar Encriptacion en las comunicaciones sensibles",
        "Monitorear el trafico de red en busca de conexiones sospechosas",
        "Implementar Politicas de Acceso restrictivas"
    ],
    "Software desactualizado": [
        "Establecer un programa de gestion de parches y actualizaciones",
        "Realizar escaneos periodicos de vulnerabilidades",
        "Implementar un ciclo de vida de software con actualizaciones obligatorias"
    ],
    "Contrasenas debiles": [
        "Implementar una Politica de Contrasenas con requisitos minimos de complejidad",
        "Activar Autenticacion de Doble Factor (2FA)",
        "Utilizar un gestor de contrasenas corporativo"
    ],
    "Configuracion incorrecta": [
        "Realizar auditorias periodicas de configuracion",
        "Implementar estandares de hardening (CIS Benchmarks)",
        "Automatizar la configuracion con herramientas IaC (Infrastructure as Code)"
    ]
}


# --- Motor del Agente -----------------------------------------------------

def agente_recomienda(g):
    """
    Motor principal del agente.
    Analiza la ontologia y genera recomendaciones basadas en:
    1. Las amenazas detectadas
    2. Los niveles de riesgo
    3. La criticidad de los activos
    4. Las mitigaciones existentes
    """

    print("")
    print("=" * 70)
    print("  AGENTE INTELIGENTE DE CIBERSEGURIDAD")
    print("  Analisis y Recomendaciones basadas en la Ontologia")
    print("=" * 70)

    # -- Paso 1: Explorar la ontologia --
    print("")
    print("[PASO 1] Explorando la ontologia...")
    clases = listar_clases(g)
    print("   Clases encontradas ({}):".format(len(clases)))
    for c in clases:
        print("     - {}".format(c))

    # -- Paso 2: Identificar individuos --
    print("")
    print("[PASO 2] Identificando individuos (instancias)...")
    individuos = listar_individuos(g)
    for tipo, lista in individuos.items():
        print("   [{}]".format(tipo))
        for ind in lista:
            print("     - {}".format(ind))

    # -- Paso 3: Analizar amenazas --
    print("")
    print("[PASO 3] Analizando amenazas en la ontologia...")
    amenazas = obtener_amenazas(g)
    print("   Tipos de amenaza encontrados: {}".format(", ".join(amenazas)))

    # -- Paso 4: Evaluar niveles de riesgo --
    print("")
    print("[PASO 4] Evaluando niveles de riesgo...")
    riesgos = obtener_nivel_riesgo(g)
    if riesgos:
        for nombre, nivel in riesgos:
            if nivel >= 4:
                etiqueta = "ALTO"
            elif nivel >= 2:
                etiqueta = "MEDIO"
            else:
                etiqueta = "BAJO"
            print("   {} : Nivel {}/5 -- {}".format(nombre, nivel, etiqueta))
    else:
        print("   No se encontraron niveles de riesgo asignados.")

    # -- Paso 5: Evaluar criticidad de activos --
    print("")
    print("[PASO 5] Evaluando criticidad de activos...")
    criticos = obtener_criticidad(g)
    if criticos:
        for nombre, nivel in criticos:
            if nivel >= 4:
                etiqueta = "CRITICO"
            elif nivel >= 2:
                etiqueta = "IMPORTANTE"
            else:
                etiqueta = "NORMAL"
            print("   {} : Criticidad {}/5 -- {}".format(nombre, nivel, etiqueta))
    else:
        print("   No se encontraron niveles de criticidad asignados.")

    # -- Paso 6: Revisar mitigaciones existentes --
    print("")
    print("[PASO 6] Revisando controles de mitigacion existentes...")
    mitigaciones = obtener_mitigaciones(g)
    if mitigaciones:
        for control, amenaza in mitigaciones:
            print("   [OK] {} --mitiga--> {}".format(control, amenaza))
    else:
        print("   No se encontraron relaciones de mitigacion definidas.")

    # -- Paso 7: Generar recomendaciones --
    print("")
    print("=" * 70)
    print("  RECOMENDACIONES DEL AGENTE")
    print("=" * 70)

    recomendaciones_emitidas = False

    # Recomendar segun amenazas detectadas
    for amenaza in amenazas:
        if amenaza in REGLAS_RECOMENDACION:
            recomendaciones_emitidas = True
            print("")
            print("  >> Para la amenaza '{}':".format(amenaza))
            for rec in REGLAS_RECOMENDACION[amenaza]:
                print("     -> {}".format(rec))

    # Recomendar segun vulnerabilidades
    vulnerabilidades = obtener_vulnerabilidades(g)
    for vuln in vulnerabilidades:
        if vuln in REGLAS_RECOMENDACION:
            recomendaciones_emitidas = True
            print("")
            print("  >> Para la vulnerabilidad '{}':".format(vuln))
            for rec in REGLAS_RECOMENDACION[vuln]:
                print("     -> {}".format(rec))

    # Recomendaciones basadas en riesgo alto
    for nombre, nivel in riesgos:
        if nivel >= 4:
            recomendaciones_emitidas = True
            print("")
            print("  !! ALERTA: '{}' tiene riesgo ALTO (nivel {}).".format(nombre, nivel))
            print("     -> Se recomienda accion inmediata y priorizar la mitigacion.")
            print("     -> Verificar que existan controles activos para esta amenaza.")

    # Recomendaciones basadas en criticidad alta
    for nombre, nivel in criticos:
        if nivel >= 4:
            recomendaciones_emitidas = True
            print("")
            print("  !! ALERTA: El activo '{}' es CRITICO (nivel {}).".format(nombre, nivel))
            print("     -> Asegurar que tiene controles de proteccion dedicados.")
            print("     -> Implementar monitoreo continuo y respaldo automatico.")

    if not recomendaciones_emitidas:
        print("")
        print("  (i) No se generaron recomendaciones especificas.")

    # -- Resumen --
    controles = obtener_controles(g)
    print("")
    print("=" * 70)
    print("  RESUMEN DEL ANALISIS")
    print("=" * 70)
    print("   Amenazas identificadas:       {}".format(len(amenazas)))
    print("   Vulnerabilidades detectadas:  {}".format(len(vulnerabilidades)))
    print("   Controles disponibles:        {}".format(len(controles)))
    print("   Mitigaciones activas:         {}".format(len(mitigaciones)))
    print("   Activos criticos:             {}".format(len([c for _, c in criticos if c >= 4])))
    print("   Amenazas de riesgo alto:      {}".format(len([r for _, r in riesgos if r >= 4])))
    print("=" * 70)


# --- Ejecucion Principal --------------------------------------------------

if __name__ == "__main__":
    print("Iniciando Agente de Ciberseguridad...")
    print("   Cargando ontologia desde: {}".format(os.path.abspath(RUTA_ONTOLOGIA)))

    try:
        grafo = cargar_ontologia(RUTA_ONTOLOGIA)
        agente_recomienda(grafo)
    except FileNotFoundError:
        print("ERROR: No se encontro el archivo de ontologia en '{}'".format(RUTA_ONTOLOGIA))
        print("   Asegurate de que 'ontologia.owl' este en la raiz del repositorio.")
    except Exception as e:
        print("ERROR inesperado: {}".format(e))
