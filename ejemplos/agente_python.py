"""
Actividad 9: Agente basado en ontología
Fecha: 04/05/2026
Autor: Luis Daniel Peña Gaytán
"""

from rdflib import Graph, Namespace

url = "https://raw.githubusercontent.com/danielpegat/ontologia-ciberseguridad/main/ontologia.owl"
g = Graph()
g.parse(url, format="xml")

ns = Namespace("http://www.miOntologia.org/ciberseguridad#")

class AgenteCiberseguridad:
    def __init__(self, grafo):
        self.grafo = grafo

    def recomendar(self, amenaza):
        consulta = f"""
        SELECT ?control WHERE {{
            ?control <{ns.Mitiga}> <{amenaza}> .
        }}
        """
        return [str(r[0]).split("#")[-1] for r in self.grafo.query(consulta)]

agente = AgenteCiberseguridad(g)
print("Controles para Phishing Corporativo:", agente.recomendar(ns.Phishing_Corporativo))
