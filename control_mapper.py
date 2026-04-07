"""
Lesson 5: Control Mapping with Dictionaries
=============================================
A GRC tool that maps NIST 800-53 controls to CIS, ISO 27001, and SOC 2 controls.
Supports lookups, searching, adding new mappings, and saving to JSON.

Python concepts covered:
  - Dictionaries: creation, nesting, .get(), .items(), .keys()
  - JSON: json.load(), json.dump() for persistent storage
  - Interactive input loop (menu-driven CLI)
  - Nested data structures (dicts of dicts of lists)

GRC relevance:
  - Cross-framework compliance mapping
  - NIST 800-53, CIS Benchmarks, ISO 27001, SOC 2
"""

import json
import sys
import os


# ─── CONFIGURATION ────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAPPINGS_FILE = os.path.join(SCRIPT_DIR, "control_mappings.json")


# ─── DATA FUNCTIONS ───────────────────────────────────────────────────

def load_mappings(filepath):
    """
    Load control mappings from a JSON file.

    json.load() reads a JSON file and converts it to Python objects:
      - JSON objects {} become Python dicts
      - JSON arrays [] become Python lists
      - JSON strings become Python strings

    This is called "deserialization" — converting stored data back
    into usable Python objects.
    """
    if not os.path.exists(filepath):
        print(f"  No mappings file found at: {filepath}")
        print("  Starting with empty mappings.\n")
        return {}

    with open(filepath, "r", encoding="utf-8") as f:
        # json.load() reads from a file object
        data = json.load(f)

    return data


def save_mappings(mappings, filepath):
    """
    Save control mappings to a JSON file.

    json.dump() writes Python objects to a JSON file:
      - indent=2 makes it human-readable (pretty-printed)
      - sort_keys=True puts keys in alphabetical order
      - ensure_ascii=False allows special characters

    This is called "serialization" — converting Python objects
    into a storable format.
    """
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(mappings, f, indent=2, sort_keys=True, ensure_ascii=False)

    print(f"  💾 Mappings saved to: {filepath}\n")


# ─── LOOKUP FUNCTIONS ─────────────────────────────────────────────────

def lookup_control(mappings, control_id):
    """
    Look up a single control by ID and display its mappings.

    .get() is safer than direct access with []:
      mappings.get("AC-2")       → returns the value, or None if missing
      mappings["AC-2"]           → raises KeyError if missing

    .get() with a default:
      mappings.get("AC-2", {})   → returns {} if missing (instead of None)
    """
    # .upper() normalizes input so "ac-2" matches "AC-2"
    control_id = control_id.strip().upper()

    # .get() returns None if the key doesn't exist
    control = mappings.get(control_id)

    if not control:
        print(f"\n  Control '{control_id}' not found in mappings.")
        print(f"  Use 'list' to see available controls, or 'add' to create a new mapping.\n")
        return

    print(f"\n  {'─' * 55}")
    print(f"  NIST 800-53: {control_id} — {control.get('title', 'N/A')}")
    print(f"  Family: {control.get('family', 'N/A')}")
    print(f"  {'─' * 55}")

    # .get() with default empty dict — safe even if 'mappings' key is missing
    framework_mappings = control.get("mappings", {})

    if not framework_mappings:
        print("  No cross-framework mappings defined.\n")
        return

    # .items() returns (key, value) pairs from a dictionary
    # Here: key = framework name, value = list of mapped controls
    for framework, controls in framework_mappings.items():
        print(f"\n  {framework}:")
        # controls is a list — we loop through it
        for mapped_control in controls:
            print(f"    → {mapped_control}")

    print()


def list_controls(mappings):
    """
    List all controls in the mapping database.

    .keys() returns all keys in a dictionary.
    sorted() sorts them alphabetically.
    """
    if not mappings:
        print("\n  No controls in the database.\n")
        return

    print(f"\n  {'─' * 55}")
    print(f"  CONTROL MAPPING DATABASE")
    print(f"  Total controls: {len(mappings)}")
    print(f"  {'─' * 55}")

    # sorted() with key=str sorts the control IDs alphabetically
    print(f"\n  {'Control':<10} {'Title':<35} {'Frameworks'}")
    print(f"  {'-'*10} {'-'*35} {'-'*15}")

    for control_id in sorted(mappings.keys()):
        control = mappings[control_id]
        title = control.get("title", "N/A")
        # Get the framework names from the nested mappings dict
        frameworks = ", ".join(control.get("mappings", {}).keys())
        print(f"  {control_id:<10} {title:<35} {frameworks}")

    print()


def search_controls(mappings, search_term):
    """
    Search across all controls and mappings for a term.

    Demonstrates iterating over nested data structures:
    for each control → for each framework → for each mapped control
    """
    search_term = search_term.strip().lower()
    results = []

    # .items() gives us both the key and value in one loop
    for control_id, control in mappings.items():
        # Search in control ID, title, and family
        if (search_term in control_id.lower() or
                search_term in control.get("title", "").lower() or
                search_term in control.get("family", "").lower()):
            results.append((control_id, control.get("title", ""), "Control ID/Title/Family"))
            continue

        # Search in mapped controls (nested loop)
        for framework, controls in control.get("mappings", {}).items():
            for mapped_control in controls:
                if search_term in mapped_control.lower():
                    results.append((control_id, control.get("title", ""), f"Mapped in {framework}: {mapped_control}"))
                    break

    if not results:
        print(f"\n  No results found for '{search_term}'.\n")
        return

    print(f"\n  Search results for '{search_term}': ({len(results)} matches)")
    print(f"  {'─' * 55}")

    for control_id, title, match_location in results:
        print(f"  {control_id:<10} {title}")
        print(f"             Found in: {match_location}")

    print()


def add_mapping(mappings):
    """
    Interactively add a new control or mapping.

    Shows how to build up nested dictionary structures step by step.
    """
    print(f"\n  {'─' * 55}")
    print("  ADD NEW CONTROL MAPPING")
    print(f"  {'─' * 55}")

    control_id = input("\n  NIST 800-53 Control ID (e.g. AC-2): ").strip().upper()

    if not control_id:
        print("  Cancelled.\n")
        return

    # Check if control already exists
    if control_id in mappings:
        print(f"  Control '{control_id}' already exists. Adding framework mapping to it.")
        control = mappings[control_id]
    else:
        # Create a new control entry — building a nested dict
        title = input("  Control title: ").strip()
        family = input("  Control family (e.g. Access Control): ").strip()

        # This creates a new nested dictionary structure
        control = {
            "title": title,
            "family": family,
            "mappings": {}
        }
        mappings[control_id] = control
        print(f"  Created new control: {control_id}")

    # Add a framework mapping
    framework = input("  Framework to map to (e.g. CIS, ISO27001, SOC2): ").strip()

    if not framework:
        print("  No framework specified. Control saved without new mappings.\n")
        return

    mapped_control = input(f"  {framework} control reference: ").strip()

    if not mapped_control:
        print("  No mapping entered. Cancelled.\n")
        return

    # Initialize the framework list if it doesn't exist
    # .setdefault() returns the value if key exists,
    # or sets it to the default and returns that
    framework_list = control.get("mappings", {})
    if framework not in framework_list:
        framework_list[framework] = []

    framework_list[framework].append(mapped_control)
    control["mappings"] = framework_list

    print(f"\n  ✅ Added: {control_id} → {framework}: {mapped_control}")

    # Ask to save
    save = input("  Save to file? (y/n): ").strip().lower()
    if save == "y":
        save_mappings(mappings, MAPPINGS_FILE)
    else:
        print("  Changes kept in memory only (will be lost on exit).\n")


def show_stats(mappings):
    """Show summary statistics about the mapping database."""
    if not mappings:
        print("\n  Database is empty.\n")
        return

    total_controls = len(mappings)

    # Collect all unique frameworks and families
    frameworks = set()
    families = set()
    total_mapped = 0

    for control in mappings.values():
        families.add(control.get("family", "Unknown"))
        for framework, controls in control.get("mappings", {}).items():
            frameworks.add(framework)
            total_mapped += len(controls)

    print(f"\n  {'─' * 40}")
    print(f"  MAPPING DATABASE STATS")
    print(f"  {'─' * 40}")
    print(f"  NIST 800-53 controls:  {total_controls}")
    print(f"  Frameworks mapped:     {len(frameworks)} ({', '.join(sorted(frameworks))})")
    print(f"  Control families:      {len(families)}")
    print(f"  Total cross-mappings:  {total_mapped}")
    print(f"  {'─' * 40}\n")


# ─── INTERACTIVE MENU ─────────────────────────────────────────────────

def show_menu():
    """Print the interactive menu."""
    print("  ┌─────────────────────────────────────┐")
    print("  │  🗺️  GRC Control Mapper              │")
    print("  ├─────────────────────────────────────┤")
    print("  │  lookup <id>  - Look up a control   │")
    print("  │  list         - List all controls   │")
    print("  │  search <term>- Search mappings     │")
    print("  │  add          - Add new mapping     │")
    print("  │  stats        - Database stats      │")
    print("  │  save         - Save to file        │")
    print("  │  help         - Show this menu      │")
    print("  │  quit         - Exit                │")
    print("  └─────────────────────────────────────┘")


def interactive_mode(mappings):
    """
    Run an interactive menu loop.

    A while True loop runs forever until we explicitly break out of it.
    This is a common pattern for interactive CLI tools.
    """
    print(f"\n  Loaded {len(mappings)} controls from {MAPPINGS_FILE}\n")
    show_menu()

    while True:
        # input() in a loop = interactive prompt
        user_input = input("\n  > ").strip()

        if not user_input:
            continue

        # Split into command and arguments
        # "lookup AC-2" → parts = ["lookup", "AC-2"]
        parts = user_input.split(maxsplit=1)
        command = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if command == "quit" or command == "exit" or command == "q":
            print("  Goodbye!\n")
            break

        elif command == "help":
            show_menu()

        elif command == "lookup":
            if not arg:
                arg = input("  Enter control ID: ").strip()
            lookup_control(mappings, arg)

        elif command == "list":
            list_controls(mappings)

        elif command == "search":
            if not arg:
                arg = input("  Enter search term: ").strip()
            search_controls(mappings, arg)

        elif command == "add":
            add_mapping(mappings)

        elif command == "stats":
            show_stats(mappings)

        elif command == "save":
            save_mappings(mappings, MAPPINGS_FILE)

        else:
            # Maybe they typed just a control ID directly
            if command.upper() in mappings:
                lookup_control(mappings, command)
            else:
                print(f"  Unknown command: '{command}'. Type 'help' for options.")


# ─── MAIN ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mappings = load_mappings(MAPPINGS_FILE)

    # If a control ID is passed as argument, do a quick lookup and exit
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg.lower() == "help":
            show_menu()
        elif arg.lower() == "list":
            list_controls(mappings)
        elif arg.lower() == "stats":
            show_stats(mappings)
        else:
            lookup_control(mappings, arg)
        sys.exit(0)

    # Otherwise, run interactive mode
    interactive_mode(mappings)
