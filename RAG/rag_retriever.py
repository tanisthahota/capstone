from vector_store import VectorStoreManager
from knowledge_base import get_threat_by_id

class RAGRetriever:
    def __init__(self, vector_store_manager: VectorStoreManager):
        self.vector_store = vector_store_manager
    
    def retrieve_threat_context(self, layer: str, query: str, top_k: int = 3):
        similar_threats = self.vector_store.search_threats(layer, query, top_k)
        enriched_results = []
        for threat in similar_threats:
            threat_id = threat['threat_id']
            full_threat = get_threat_by_id(threat_id)
            
            if full_threat:
                enriched_results.append({
                    "threat_id": threat_id,
                    "name": full_threat['name'],
                    "category": full_threat['category'],
                    "description": full_threat['description'],
                    "indicators": full_threat['indicators'],
                    "impact": full_threat['impact'],
                    "remediation": full_threat['remediation'],
                    "mitre_id": full_threat['mitre_id'],
                    "similarity_score": 1 - threat['distance']  # Convert distance to similarity
                })
        
        return enriched_results
    
    def analyze_unknown_threat(self, layer: str, event_data: str):
        
        similar_threats = self.retrieve_threat_context(layer, event_data, top_k=3)
        
        if not similar_threats:
            return {
                "status": "no_match",
                "message": "No similar threats found in knowledge base",
                "layer": layer
            }
        
        # Build analysis
        analysis = {
            "status": "unknown_threat_detected",
            "layer": layer,
            "event_description": event_data,
            "similar_threats": similar_threats,
            "top_match": similar_threats[0] if similar_threats else None,
            "confidence": similar_threats[0]['similarity_score'] if similar_threats else 0,
            "recommendations": self._generate_recommendations(similar_threats)
        }
        
        return analysis
    
    def _generate_recommendations(self, threats: list):
        """Generate security recommendations based on retrieved threats"""
        recommendations = []
        
        # Collect unique remediations
        seen_remediations = set()
        for threat in threats:
            remediation = threat.get('remediation', '')
            if remediation and remediation not in seen_remediations:
                recommendations.append(remediation)
                seen_remediations.add(remediation)
        
        return recommendations[:3]  # Top 3 recommendations
