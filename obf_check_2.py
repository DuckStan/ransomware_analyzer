import os
import subprocess
import json
import pefile


def is_packed(file_path):
    print(file_path)
    detect_it_easy_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Detect_It_Easy', 'diec.exe')
    cmd = [detect_it_easy_path, '--json', '-d', '-e', '-a', os.path.abspath(file_path)]
    output = subprocess.check_output(cmd, shell=True)
    result = json.loads(output.decode())
    print(result)

    total_entropy = result['total']
    is_exe_packed = result['status']
    packed_sections= []
    #print(result)

    packed_number = 0
    for record in result['records']:
        if record['status'] == 'packed':
            packed_sections.append(record)
            packed_number += 1
    packed_section_count = len(packed_sections)
    print(packed_section_count)

    # Считаем оценку энтропии
    min_entropy = 0.0
    max_entropy = 8.0
    entropy_score = (total_entropy - min_entropy) / (max_entropy - min_entropy)

    pe = pefile.PE(file_path)
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    if directory.VirtualAddress == 0:
        print("NOOOO")
        certificate = None
    else:
        certificate = pe.write()[directory.VirtualAddress + 8:]
    #print(certificate)
    '''
    try:
        print(pe.verify_checksum(certificate=certificate))
        print("YES CERTIFICATE")
    except Exception as e:
        print("NO CERTIFICATE")
        print(e)
    '''
    # Подсчёт балла по кол-ву упакованных секций
    packed_score = packed_number / len(result['records'])
    legitimacy_score = 1
    legitimacy_status = "Suspicious"
    packed_section_names = []
    #packed_size = 0
    if certificate is None:
        legitimacy_score -= 0.2
    if packed_section_count > 0:
        # Check if there are headers that refer packers (like UPX)
        for record in packed_sections:
            if record['status'] == 'packed':
                #packed_section_names.append(record['name'])
                #packed_size += record['size']
                if 'upx' in record['name'].lower():
                    #legitimacy_status = "Likely ransomware"
                    legitimacy_score -= 0.4
                elif '.text' in record['name'].lower() and record['size'] > 40000:
                    #legitimacy_status = "Likely ransomware"
                    legitimacy_score -= 0.4

                '''    
                elif record['name'] == 'Overlay' and record['status'] == 'packed':
                    packed_overlay_size = record['size']
                    if packed_overlay_size > 10000:
                        legitimacy_status = "Likely legitimate"
                        legitimacy_score = 0.8
                '''
    #packed_score = packed_size / os.path.getsize(file_path)

    if legitimacy_score >= 0.8:
        legitimacy_status = "Likely legitimate"
    elif legitimacy_score >= 0.6:
        legitimacy_status = "Suspicious"
    else:
        legitimacy_status = "Likely ransomware"

    # Высчитывание финального балла
    entropy_weight = 30
    packed_weight = 30
    legitimacy_weight = 40
    final_score = (entropy_weight * entropy_score) + (packed_weight * packed_score) + (
                legitimacy_weight * (1 - legitimacy_score))

    # Возвращаем результаты
    return {
        'score': final_score,
        'is_packed': is_exe_packed,
        'packed_sections': packed_section_names,
        'legitimacy_status(subjective)': legitimacy_status,
        'legitimacy_score(subjective)': legitimacy_score
    }

