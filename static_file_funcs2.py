import pefile
import os
import json

# Список WinAPI функций, ассоциируемых с Ransomware
ransomware_api_calls = [
    'CryptEncrypt',
    'CryptDecrypt',
    'CryptGenKey',
    'CryptDestroyKey',
    'CryptReleaseContext',
    'CreateFile',
    'WriteFile',
    'ReadFile',
    'MoveFile'
    'CopyFile',
    'GetSystemDirectory',
    'GetWindowsDirectory',
    'SetCurrentDirectory',
    'CreateDirectory'
    'GetFileAttributes',
    'GetFileSize',
    'SetFileAttributes',
    'SearchPath',
    'GetShortPathName',
    'GetFullPathName'
]


def detect_ransomware(file_path):
    results = {}
    print(file_path)
    # существует ли файл
    if not os.path.exists(file_path):
        results['error'] = f"File {file_path} does not exist!"
        return json.dumps(results)

    # инициализируем объект pefile c помощью исполняемого файла
    try:
        pe = pefile.PE(file_path)
    except:
        results['error'] = f"File {file_path} is not a valid PE file!"
        return json.dumps(results)

    imports = []
    ransomware_functions = []
    import_funcs_count = 0
    # Ищем Ransomware winAPI вызовы в таблице импортов
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            module = entry.dll.decode().lower()
            if module not in imports:
                #print(module)
                imports.append(module)
            for imp in entry.imports:
                if imp.name:
                    import_funcs_count += 1
                    str_func = bytes.decode(imp.name, 'utf-8')
                    for api_call in ransomware_api_calls:
                        if api_call in str_func:
                            if api_call not in ransomware_functions:
                                ransomware_functions.append(api_call)

    #imports_count = len(imports)
    ransomware_functions_count = len(ransomware_functions)

    # Высчитываем балл вероятности принадлежности к Ransomware на основе кол-ва и названий импортируемых функций
    if ransomware_functions_count >= 3 and import_funcs_count <= 50:
        results['score'] = 100
        results['message'] = 'Highly likely ransomware'
    elif ransomware_functions_count > 0 and import_funcs_count <= 100:
        results['score'] = 80
        results['message'] = 'Likely ransomware'
    elif ransomware_functions_count == 0 and import_funcs_count <= 10:
        results['score'] = 40
        results['message'] = 'Potentially suspicious'
    else:
        results['score'] = 0
        results['message'] = 'Not ransomware'

    results['imports_count'] = import_funcs_count
    results['ransomware_functions_count'] = ransomware_functions_count

    if ransomware_functions:
        results['ransomware_functions'] = ransomware_functions

    # Возвращаем отчёт
    return results
