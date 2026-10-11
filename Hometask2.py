file_system = {
        "/": ["home", "var", "etc", "tmp", "opt"],
        "home": ["alice", "bob", "sara", "shared"],
        "alice": ["resume.pdf", "notes.txt", "projects"],
        "projects": ["ai_lab4.py", "bfs_dfs.ipynb", "data"],
        "data": ["network.csv", "passwords_backup.txt", "scan_results.json"],
        "bob": ["report.docx", "downloads"],
        "downloads": ["setup.exe", "lecture_video.mp4", "invoice.pdf"],
        "sara": ["thesis_draft.docx", "keylogger_test.py"],
        "shared": ["timetable.xlsx", "policy.pdf", "lab_files"],
        "lab_files": ["lab01.py", "lab02.py", "lab03.py"],
        "var": ["www", "log"],
        "www": ["html", "uploads", "logs"],
        "html": ["index.html", "login.php", "style.css"],
        "uploads": ["photo1.jpg", "shell.php", "brochure.pdf"],
        "logs": ["access.log", "error.log"],
        "log": ["syslog", "auth.log"],
        "etc": ["passwd", "shadow", "hosts", "ssh", "cron.d"],
        "ssh": ["sshd_config", "authorized_keys"],
        "cron.d": ["backup_job", "cleanup_job"],
        "tmp": ["session_a1.tmp", ".hidden_miner"],
        "opt": ["tools"],
        "tools": ["scan.sh", "monitor.py"],
    }
tree=dict(file_system)
for children in file_system.values():
    for name in children:
        tree.setdefault(name, [])




directory_list=[]

def walk_system(current_node,directories):
        directory_list.append(current_node)
        for directory in directories[current_node]:
            walk_system(directory,directories)

walk_system("/", tree)


def print_tree(current_node, graph, depth=0):
    print('  '*(4*depth)+current_node)
    for child in graph[current_node]:
        print_tree(child, graph, depth + 1)
print_tree("/",tree)


def print_paths(current_node, graph, current_path=""):
    if current_node == "/":
        new_path = "/"
    else:
        if current_path == "/":
            new_path = current_path + current_node
        else:
            new_path = current_path + "/" + current_node

    print(new_path)

    for child in graph[current_node]:
        print_paths(child, graph, new_path)

print("\n ===PART A PATH_SYSTEM ===")
print_paths("/", tree)


#PART B
file_sizes = {
    "resume.pdf": 220, "notes.txt": 4, "ai_lab4.py": 6, "bfs_dfs.ipynb": 85,
    "network.csv": 340, "passwords_backup.txt": 12, "scan_results.json": 96,
    "report.docx": 150, "setup.exe": 5200, "lecture_video.mp4": 48000, "invoice.pdf": 90,
    "thesis_draft.docx": 1200, "keylogger_test.py": 14, "timetable.xlsx": 58, "policy.pdf": 310,
    "lab01.py": 3, "lab02.py": 4, "lab03.py": 5, "index.html": 12, "login.php": 8,
    "style.css": 15, "photo1.jpg": 820, "shell.php": 7, "brochure.pdf": 450,
    "access.log": 15000, "error.log": 800, "syslog": 2200, "auth.log": 640,
    "passwd": 3, "shadow": 2, "hosts": 1, "sshd_config": 4, "authorized_keys": 2,
    "backup_job": 1, "cleanup_job": 1, "session_a1.tmp": 1, ".hidden_miner": 3400,
    "scan.sh": 2, "monitor.py": 9,
}

suspicious_files_list = []


def find_suspicious(current_node, graph, inside_uploads=False):
    if current_node.endswith(".exe"):
        suspicious_files_list.append(current_node)

    elif current_node.endswith(".php") and inside_uploads:
        suspicious_files_list.append(current_node)

    elif "password" in current_node.lower() or "keylogger" in current_node.lower():
        suspicious_files_list.append(current_node)

    elif current_node.startswith(".") and file_sizes.get(current_node, 0) > 1000:
        suspicious_files_list.append(current_node)

    for child in graph[current_node]:

        if child == "uploads" or inside_uploads:
            find_suspicious(child, graph, True)
        else:
            find_suspicious(child, graph, inside_uploads)

folder_sizes_report = {}


def get_folder_size(current_node, graph):
    current_size = file_sizes.get(current_node, 0)

    for child in graph[current_node]:
        current_size = current_size + get_folder_size(child, graph)


    if current_node == "/" or current_node in file_system:
        folder_sizes_report[current_node] = current_size

    return current_size



print("\n=== PART B: FORENSIC SCAN RESULTS ===")

find_suspicious("/", tree)
print("Suspicious Files Found:", suspicious_files_list)
get_folder_size("/", tree)
print("Folder Size of '/':", folder_sizes_report.get("/"), "KB")
print("Folder Size of 'home':", folder_sizes_report.get("home"), "KB")
print("Folder Size of 'var':", folder_sizes_report.get("var"), "KB")
print("Folder Size of 'etc':", folder_sizes_report.get("etc"), "KB")



# PART C


def audit_system_via_bfs(network_graph, root_directory="/"):
    bfs_discovered_threats = []
    items_count_per_level = {}

    bfs_frontier = [(root_directory, 0, False)]
    already_evaluated = set()

    while bfs_frontier:

        item, current_depth, is_inside_uploads = bfs_frontier.pop(0)

        if item in already_evaluated:
            continue
        already_evaluated.add(item)


        if current_depth in items_count_per_level:
            items_count_per_level[current_depth] = items_count_per_level[current_depth] + 1
        else:
            items_count_per_level[current_depth] = 1


        file_weight = file_sizes.get(item, 0)
        is_malicious = False

        if item.endswith(".exe"):
            is_malicious = True
        elif item.endswith(".php") and is_inside_uploads:
            is_malicious = True
        elif "password" in item.lower() or "keylogger" in item.lower():
            is_malicious = True
        elif item.startswith(".") and file_weight > 1000:
            is_malicious = True

        if is_malicious:
            bfs_discovered_threats.append(item)


        for sub_node in network_graph[item]:
            check_uploads_status = (sub_node == "uploads" or is_inside_uploads)
            bfs_frontier.append((sub_node, current_depth + 1, check_uploads_status))

    return bfs_discovered_threats, items_count_per_level

print("\n=== PART C: BFS ANALYSIS RESULTS (SIMPLE LIST) ===")


malware_by_bfs, level_distribution = audit_system_via_bfs(tree)

print("Threats Found in BFS Order:", malware_by_bfs)
print("Items Count Level-by-Level (Depth Structure):")
for depth_key in sorted(level_distribution.keys()):
    print(f"Depth {depth_key}: Contains {level_distribution[depth_key]} items")



#PART D

cyclic_tree = {}
for parent_key, children_list in tree.items():
    cyclic_tree[parent_key] = list(children_list)

cyclic_tree["alice"].append("shared")
cyclic_tree["shared"].append("www")
cyclic_tree["tmp"].append("home")

def find_safe_dfs_route(graph, start_point, target_goal):
    dfs_stack = [(start_point, [start_point])]
    visited_nodes = set()

    while dfs_stack:

        node, current_route = dfs_stack.pop()

        if node == target_goal:
            return current_route

        if node not in visited_nodes:
            visited_nodes.add(node)
            for child in reversed(graph[node]):
                if child not in visited_nodes:
                    dfs_stack.append((child, current_route + [child]))

    return None



def find_safe_bfs_route(graph, start_point, target_goal):
    bfs_queue = [(start_point, [start_point])]
    visited_nodes = {start_point}

    while bfs_queue:
        node, current_route = bfs_queue.pop(0)

        if node == target_goal:
            return current_route

        for child in graph[node]:
            if child not in visited_nodes:
                visited_nodes.add(child)
                bfs_queue.append((child, current_route + [child]))

    return None


print("\n=== PART D: SHORTCUT LOOP ANALYSIS RESULTS ===")


dfs_recovered_path = find_safe_dfs_route(cyclic_tree, "/", "shell.php")
bfs_recovered_path = find_safe_bfs_route(cyclic_tree, "/", "shell.php")


print("DFS Recovery Route to shell.php:", " -> ".join(dfs_recovered_path) if dfs_recovered_path else "Not Found")
print("BFS Recovery Route to shell.php:", " -> ".join(bfs_recovered_path) if bfs_recovered_path else "Not Found")