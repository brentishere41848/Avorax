import 'package:file_selector/file_selector.dart' as file_selector;

class SelectedFilePath {
  const SelectedFilePath({required this.name, required this.path});

  final String name;
  final String path;
}

class FileSelectionService {
  const FileSelectionService();

  Future<SelectedFilePath?> pickFile() async {
    final file = await file_selector.openFile();
    if (file == null) return null;
    return SelectedFilePath(name: file.name, path: file.path);
  }

  Future<String?> pickDirectory() => file_selector.getDirectoryPath();
}
