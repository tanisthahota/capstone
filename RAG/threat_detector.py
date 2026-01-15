import json
from vector_store import VectorStoreManager
from rag_retriever import RAGRetriever

class ThreatDetector:
    def __init__(self, vector_store_manager: VectorStoreManager):
        """Initialize threat detector with RAG"""
        self.vector_store = vector_store_manager
        self.rag_retriever = RAGRetriever(vector_store_manager)
        
        # Threat mappings for each layer
        self.threat_mappings = {
            "application": ["SQLi", "XSS", "Broken Auth", "Business Logic", "Deserialization", "Dependency Vuln", "Data Leak"],
            "container": ["Container Escape", "Privilege Escalation", "Insecure Image", "Secrets Exposure", "Supply Chain", "DoS"],
            "network": ["MitM", "Unencrypted Traffic", "DNS Spoofing", "DDoS", "Lateral Movement", "Replay Attack", "Port Scan"]
        }
    
    def detect_threat(self, layer: str, event_data: dict, slm_prediction: str = None, confidence: float = None):
        """
        Detect threat using SLM + RAG fallback
        
        Args:
            layer: 'application', 'container', or 'network'
            event_data: Event/log data to analyze
            slm_prediction: Prediction from SLM model (optional)
            confidence: Confidence score from SLM (optional)
        
        Returns:
            Threat detection result with classification and context
        """
        
        # If SLM has high confidence, return SLM prediction
        if slm_prediction and confidence and confidence > 0.7:
            return {
                "detection_method": "SLM_Classification",
                "layer": layer,
                "threat_type": slm_prediction,
                "confidence": confidence,
                "source": "Trained Model",
                "event_data": event_data
            }
        
        # If SLM is uncertain or predicts unknown, use RAG
        event_description = self._format_event_for_rag(event_data)
        
        rag_analysis = self.rag_retriever.analyze_unknown_threat(layer, event_description)
        
        if rag_analysis['status'] == 'unknown_threat_detected':
            return {
                "detection_method": "RAG_Retrieval",
                "layer": layer,
                "threat_type": rag_analysis['top_match']['name'],
                "threat_category": rag_analysis['top_match']['category'],
                "confidence": rag_analysis['confidence'],
                "source": "Knowledge Base (MITRE ATT&CK)",
                "similar_threats": rag_analysis['similar_threats'],
                "recommendations": rag_analysis['recommendations'],
                "event_data": event_data,
                "mitre_id": rag_analysis['top_match']['mitre_id']
            }
        else:
            return {
                "detection_method": "RAG_Retrieval",
                "layer": layer,
                "threat_type": "Unknown",
                "confidence": 0,
                "source": "No Match",
                "event_data": event_data,
                "message": "Unable to classify threat"
            }
    
    def _format_event_for_rag(self, event_data):
        """Format event data for RAG retrieval"""
        if isinstance(event_data, dict):
            return json.dumps(event_data, indent=2)
        return str(event_data)
    
    def update_slm_knowledge(self, layer: str, threat_info: dict):
        """
        Update SLM knowledge with newly detected threat
        This would integrate with your SLM retraining pipeline
        """
        return {
            "status": "update_queued",
            "layer": layer,
            "threat_info": threat_info,
            "message": "Threat added to knowledge base for SLM retraining"
        }
