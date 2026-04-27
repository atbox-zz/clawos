#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Align markdown tables by padding cells with spaces.
"""

import os
import re
import sys
from pathlib import Path

def find_markdown_files(root_dir):
    return list(Path(root_dir).rglob("*.md"))

def analyze_table(table_lines):
    if not table_lines:
        return []

    widths = []
    for line in table_lines:
        if re.match(r'^\s*\|[\s\-:|]+\|\s*$', line):
            continue
        cells = [cell.strip() for cell in line.split('|')[1:-1]]
        for i, cell in enumerate(cells):
            if i >= len(widths):
                widths.append(len(cell))
            else:
                widths[i] = max(widths[i], len(cell))
    return widths

def align_table(table_lines, column_widths):
    if not table_lines or not column_widths:
        return table_lines

    aligned_lines = []
    for line in table_lines:
        cells = [cell.strip() for cell in line.split('|')[1:-1]]

        if re.match(r'^\s*\|[\s\-:|]+\|\s*$', line):
            sep_cells = [cell.strip() for cell in line.split('|')[1:-1]]
            aligned_cells = []
            for i, cell in enumerate(sep_cells):
                if i < len(column_widths):
                    left_align = cell.startswith('-') and not cell.startswith(':-')
                    right_align = cell.endswith('-') and not cell.endswith('-:')
                    center_align = cell.startswith(':') and cell.endswith(':')

                    if center_align:
                        dashes = '-' * (column_widths[i] - 2)
                        aligned_cells.append(f':{dashes}:')
                    elif left_align:
                        dashes = '-' * (column_widths[i] - 1)
                        aligned_cells.append(f'-{dashes}:')
                    elif right_align:
                        dashes = '-' * (column_widths[i] - 1)
                        aligned_cells.append(f':{dashes}-')
                    else:
                        aligned_cells.append('-' * column_widths[i])
                else:
                    aligned_cells.append(cell)
            aligned_line = '| ' + ' | '.join(aligned_cells) + ' |'
        else:
            aligned_cells = []
            for i, cell in enumerate(cells):
                if i < len(column_widths):
                    aligned_cells.append(cell.ljust(column_widths[i]))
                else:
                    aligned_cells.append(cell)
            aligned_line = '| ' + ' | '.join(aligned_cells) + ' |'

        aligned_lines.append(aligned_line)
    return aligned_lines

def process_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        result_lines = []
        i = 0
        modified = False

        while i < len(lines):
            line = lines[i]

            if '|' in line:
                table_lines = []
                start = i

                while i < len(lines) and '|' in lines[i]:
                    table_lines.append(lines[i].rstrip('\n'))
                    i += 1

                widths = analyze_table(table_lines)
                if widths:
                    aligned = align_table(table_lines, widths)
                    result_lines.extend([l + '\n' for l in aligned])
                    if aligned != [l.rstrip('\n') for l in table_lines]:
                        modified = True
                else:
                    result_lines.extend([l + '\n' for l in table_lines])
                continue
            else:
                result_lines.append(line)
                i += 1

        if modified:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(result_lines)
            return True, len([l for l in lines if '|' in l])
        else:
            return False, 0

    except Exception as e:
        sys.stderr.write(f"Error processing {file_path}: {e}\n")
        return False, 0

def main():
    root_dir = Path.cwd()
    md_files = find_markdown_files(root_dir)

    sys.stdout.write(f"[INFO] Found {len(md_files)} markdown files\n")
    sys.stdout.write("[INFO] Aligning tables...\n\n")

    total_files = 0
    total_tables = 0

    for md_file in md_files:
        if 'target' in str(md_file) or '.git' in str(md_file):
            continue

        modified, table_count = process_file(md_file)

        if table_count > 0:
            status = "[OK] ALIGNED" if modified else "[--] (already aligned)"
            sys.stdout.write(f"{status} {md_file.relative_to(root_dir)} ({table_count} table lines)\n")
            total_files += 1
            total_tables += table_count

    sys.stdout.write(f"\n[DONE] Complete! Aligned {total_files} files with {total_tables} total table lines\n")

if __name__ == "__main__":
    main()
