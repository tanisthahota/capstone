import chromadb
import os
from knowledge_base import get_threats_by_layer, get_all_threats
from sentence_transformers import SentenceTransformer

class VectorStoreManager:
    def __init__(self, persist_dir="./chroma_db"):
        """Initialize ChromaDB with persistent storage"""
        self.persist_dir = persist_dir
        os.makedirs(persist_dir, exist_ok=True)
        
        # Initialize ChromaDB client with persistence
        try:
            # Try newer ChromaDB API
            self.client = chromadb.PersistentClient(path=persist_dir)
        except:
            # Fallback to older API
            self.client = chromadb.Client()
        
        # Initialize embedding model
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Initialize collections for each layer
        self.collections = {
            "application": self.client.get_or_create_collection(
                name="application_threats",
                metadata={"hnsw:space": "cosine"}
            ),
            "container": self.client.get_or_create_collection(
                name="container_threats",
                metadata={"hnsw:space": "cosine"}
            ),
            "network": self.client.get_or_create_collection(
                name="network_threats",
                metadata={"hnsw:space": "cosine"}
            )
        }
    
    def populate_knowledge_base(self):
        """Populate vector stores with threat knowledge base"""
        all_threats = get_all_threats()
        
        for layer_name, collection in self.collections.items():
            threats = get_threats_by_layer(layer_name)
            
            # Skip if already populated
            if collection.count() > 0:
                print(f"Collection '{layer_name}' already populated with {collection.count()} threats")
                continue
            
            documents = []
            metadatas = []
            ids = []
            
            for threat in threats:
                # Create comprehensive document for embedding
                doc = f"""
                Threat: {threat['name']}
                Category: {threat['category']}
                Description: {threat['description']}
                Indicators: {', '.join(threat['indicators'])}
                MITRE ID: {threat['mitre_id']}
                Impact: {threat['impact']}
                Remediation: {threat['remediation']}
                """
                
                documents.append(doc)
                metadatas.append({
                    "threat_id": threat["threat_id"],
                    "name": threat["name"],
                    "category": threat["category"],
                    "mitre_id": threat["mitre_id"]
                })
                ids.append(threat["threat_id"])
            
            # Add documents to collection
            collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            
            print(f"Populated '{layer_name}' collection with {len(threats)} threats")
        
        # Persist to disk
        # self.client.persist()
        print("Vector stores persisted to disk")
    
    def search_threats(self, layer: str, query: str, top_k: int = 3):
        """Search for similar threats in a specific layer"""
        if layer not in self.collections:
            return []
        
        collection = self.collections[layer]
        
        try:
            results = collection.query(
                query_texts=[query],
                n_results=top_k
            )
            
            # Format results
            threats = []
            if results['ids'] and len(results['ids']) > 0:
                for i, threat_id in enumerate(results['ids'][0]):
                    threat = {
                        "threat_id": threat_id,
                        "distance": results['distances'][0][i] if results['distances'] else 0,
                        "metadata": results['metadatas'][0][i] if results['metadatas'] else {}
                    }
                    threats.append(threat)
            
            return threats
        except Exception as e:
            print(f"Error searching threats: {e}")
            return []
    
    def add_custom_threat(self, layer: str, threat_data: dict):
        """Add a new custom threat to the vector store"""
        if layer not in self.collections:
            return False
        
        collection = self.collections[layer]
        
        doc = f"""
        Threat: {threat_data.get('name', 'Unknown')}
        Category: {threat_data.get('category', 'Unknown')}
        Description: {threat_data.get('description', '')}
        Indicators: {', '.join(threat_data.get('indicators', []))}
        Impact: {threat_data.get('impact', '')}
        Remediation: {threat_data.get('remediation', '')}
        """
        
        collection.add(
            documents=[doc],
            metadatas=[{
                "threat_id": threat_data.get("threat_id"),
                "name": threat_data.get("name"),
                "category": threat_data.get("category")
            }],
            ids=[threat_data.get("threat_id")]
        )
        
        self.client.persist()
        return True
    
    def get_threat_details(self, layer: str, threat_id: str):
        """Get detailed information about a specific threat"""
        if layer not in self.collections:
            return None
        
        collection = self.collections[layer]
        
        try:
            result = collection.get(ids=[threat_id])
            if result['ids']:
                return {
                    "threat_id": threat_id,
                    "metadata": result['metadatas'][0] if result['metadatas'] else {}
                }
        except Exception as e:
            print(f"Error getting threat details: {e}")
        
        return None
