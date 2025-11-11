from log_preprocessor import LogPreprocessor

def main():
    # Initialize
    preprocessor = LogPreprocessor()

    # BENIGN
    app_nodes = preprocessor.parse_application_logs(r'c:\Users\tanis\Documents\PROJECTS\capstone\application_logs_benign.txt')
    container_nodes = preprocessor.parse_container_logs(r'c:\Users\tanis\Documents\PROJECTS\capstone\container_logs_benign.txt')
    network_nodes = preprocessor.parse_network_logs(r'c:\Users\tanis\Documents\PROJECTS\capstone\network_logs_benign.txt')
    benign_docker = preprocessor.parse_docker_events_jsonl(r'c:\Users\tanis\Documents\PROJECTS\capstone\benign_events.jsonl', 'benign')

    # ATTACKS
    priv_esc = preprocessor.parse_docker_events_jsonl(r'c:\Users\tanis\Documents\PROJECTS\capstone\priv_esc_events.jsonl', 'priv_esc')
    reverse_shell = preprocessor.parse_docker_events_jsonl(r'c:\Users\tanis\Documents\PROJECTS\capstone\reverse_shell_events.jsonl', 'reverse_shell')
    sqli = preprocessor.parse_sqli_logs(r'c:\Users\tanis\Documents\PROJECTS\capstone\structured_sqli.log')
    brute_force = preprocessor.parse_attack_csv(r'c:\Users\tanis\Documents\PROJECTS\capstone\brute_force.csv', 'brute_force')
    dos = preprocessor.parse_attack_csv(r'c:\Users\tanis\Documents\PROJECTS\capstone\dos.csv', 'dos')
    portscan = preprocessor.parse_attack_csv(r'c:\Users\tanis\Documents\PROJECTS\capstone\portscan.csv', 'portscan')

    # Combine all (flattened correctly)
    preprocessor.nodes.extend(app_nodes)
    preprocessor.nodes.extend(container_nodes)
    preprocessor.nodes.extend(network_nodes)
    preprocessor.nodes.extend(benign_docker)
    preprocessor.nodes.extend(priv_esc)
    preprocessor.nodes.extend(reverse_shell)
    preprocessor.nodes.extend(sqli)
    preprocessor.nodes.extend(brute_force)
    preprocessor.nodes.extend(dos)
    preprocessor.nodes.extend(portscan)

    # Create edges
    temporal_edges = preprocessor.create_temporal_edges(preprocessor.nodes, time_window=10.0)
    cross_layer_edges = preprocessor.create_cross_layer_edges(preprocessor.nodes)
    preprocessor.edges.extend(temporal_edges)
    preprocessor.edges.extend(cross_layer_edges)

    # Export
    preprocessor.export_to_graph_format(r'c:\Users\tanis\Documents\PROJECTS\capstone\graph_data')

if __name__ == "__main__":
    # Replace pass with a call to main()
    main()