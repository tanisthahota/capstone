import json
from vector_store import VectorStoreManager
from threat_detector import ThreatDetector

class ThreatDetectionPipeline:
    def __init__(self, persist_dir="./chroma_db"):
        """Initialize the complete threat detection pipeline"""
        print("Initializing Threat Detection Pipeline...")
        
        # Initialize vector store
        self.vector_store = VectorStoreManager(persist_dir)
        self.vector_store.populate_knowledge_base()
        
        # Initialize threat detector
        self.threat_detector = ThreatDetector(self.vector_store)
        
        print("Pipeline initialized successfully!")
    
    def process_event(self, layer: str, event_data: dict, slm_prediction: str = None, slm_confidence: float = None):
        """
        Process a security event through the complete pipeline
        
        Args:
            layer: 'application', 'container', or 'network'
            event_data: Event/log data
            slm_prediction: Optional SLM model prediction
            slm_confidence: Optional SLM confidence score
        
        Returns:
            Complete threat detection result
        """
        
        if layer not in ["application", "container", "network"]:
            return {"error": f"Invalid layer: {layer}"}
        
        # Run threat detection
        result = self.threat_detector.detect_threat(
            layer=layer,
            event_data=event_data,
            slm_prediction=slm_prediction,
            confidence=slm_confidence
        )
        
        return result
    
    def process_batch(self, events: list):
        """Process multiple events"""
        results = []
        for event in events:
            result = self.process_event(
                layer=event.get('layer'),
                event_data=event.get('data'),
                slm_prediction=event.get('slm_prediction'),
                slm_confidence=event.get('slm_confidence')
            )
            results.append(result)
        
        return results

# Example usage
if __name__ == "__main__":
    # Initialize pipeline
    pipeline = ThreatDetectionPipeline()
    
    # Example: Application layer threat (unknown to SLM)
    app_event = {
        "type": "http_request",
        "payload": "SELECT * FROM users WHERE id=1 OR 1=1",
        "source_ip": "192.168.1.100",
        "timestamp": "2024-11-22T10:30:00Z"
    }
    
    result = pipeline.process_event(
        layer="application",
        event_data=app_event,
        slm_prediction="unknown",
        slm_confidence=0.45
    )
    
    print("\n=== Threat Detection Result ===")
    print(json.dumps(result, indent=2))
    
    # Example: Container layer threat
    container_event = {
        "type": "process_execution",
        "process": "bash",
        "user": "root",
        "parent_process": "unknown",
        "timestamp": "2024-11-22T10:35:00Z"
    }
    
    result = pipeline.process_event(
        layer="container",
        event_data=container_event,
        slm_prediction=None,
        slm_confidence=None
    )
    
    print("\n=== Container Threat Detection ===")
    print(json.dumps(result, indent=2))
    
    # Example: Network layer threat
    network_event = {
        "type": "traffic_analysis",
        "source_ip": "10.0.0.50",
        "dest_ip": "8.8.8.8",
        "port": 53,
        "protocol": "DNS",
        "query": "malicious.com",
        "timestamp": "2024-11-22T10:40:00Z"
    }
    
    result = pipeline.process_event(
        layer="network",
        event_data=network_event,
        slm_prediction="port_scan",
        slm_confidence=0.65
    )
    
    print("\n=== Network Threat Detection ===")
    print(json.dumps(result, indent=2))
