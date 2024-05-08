import obf_check_2
import os
import static_file_funcs2
import sandbox_manual
import json

if __name__ == '__main__':
    # Get the path of the "samples" folder in the current directory
    samples_folder = os.path.join(os.getcwd(), "samples")
    #script_dir = os.path.dirname(os.path.abspath(__file__))
    # Check if the "samples" folder exists
    if not os.path.exists(samples_folder):
        raise Exception("The 'samples' folder does not exist in the current directory.")

    # Get a list of all files in the "samples" folder
    files = os.listdir(samples_folder)

    # Filter the list to only include files with extensions other than ".exe"
    non_exe_files = []

    for file in files:
        file_path = os.path.join(samples_folder, file)
        if os.path.isfile(file_path) and not file.lower().endswith('.exe'):
            non_exe_files.append(file_path)

    # Rename the non-.exe files to have the ".exe" extension
    for file in non_exe_files:
        new_name = os.path.splitext(file)[0] + ".exe"
        os.rename(file, new_name)

    # Get a list of all executable files in the "samples" folder
    executable_files = []

    for file in os.listdir(samples_folder):
        file_path = os.path.join(samples_folder, file)
        if os.path.isfile(file_path) and file.lower().endswith('.exe'):
            executable_files.append(file_path)

    # Print the list of executable files
    for file in executable_files:
        print(file)

    #final json file

    # Perform the same operations as before on the executable files
    for file in executable_files:
        results = {}
        #print(os.path.splitext(file))
        name = os.path.basename(file)
        name = os.path.splitext(name)[0]
        print(name)
        results[name] = {}

        static_detection = static_file_funcs2.detect_ransomware(file)
        print(static_detection)
        results[name]['static_detection'] = static_detection

        packer_detection = obf_check_2.is_packed(file)
        results[name]['packer_detection'] = packer_detection

        sandbox_detection = sandbox_manual.is_ransomware(file)
        results[name]['sandbox_detection'] = sandbox_detection
        print(results[name]['sandbox_detection'])
        # Weights for each module
        sandbox_detection = results[name]['sandbox_detection']
        if int(sandbox_detection['score']) == 100:
            weights = {
                'static_detection': 0.1,
                'packer_detection': 0.1,
                'sandbox_detection': 0.8
            }
        else:
            weights = {
                'static_detection': 0.8,
                'packer_detection': 0.2,
                'sandbox_detection': 0.0
            }

        # Подсчитываем финальный балл
        final_score = sum([v['score'] * weights[k] for k, v in results[name].items() if 'score' in v])
        results[name]['final_score'] = final_score
        # Вердикт
        if int(results[name]['final_score']) > 60:
            results[name]['final_type'] = 'Ransomware'
        elif int(results[name]['final_score']) > 40:
            results[name]['final_type'] = 'Suspicious'
        else:
            results[name]['final_type'] = 'Likely legitimate'

        script_dir = os.path.dirname(os.path.abspath(__file__))
        print(script_dir)
        results_folder = os.path.join(script_dir, 'results')
        print(results_folder)
        if not os.path.exists(results_folder):
            os.mkdir(results_folder)
        print(name)
        results_file = os.path.join(results_folder, f"{name}.json")
        print(results_file)
        with open(results_file, 'w') as f:
            json.dump(results[name], f)


