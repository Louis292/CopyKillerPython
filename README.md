# CopyKillerPython V1.0
 
 ## Introduction

 CopyKillerPython is a classic logicel for delete a copy files.
 Is a classic logicel for delete a copy and use a 'thinker' gui model

 ## Installation:
 - Download the project
 - Extract the zip folder
 - Execute : ``python3 main.py`` or open the ``start.bat``
 - Select your folder and clear !
 - Select your extention in config button
 - and enjoy!

## Configuration

Edit with the ``Configuration`` button and select your extention

```JSON
{
    "window_title": "Détecteur de fichiers en double",
    "extensions": {
        "images": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"],
        "documents": [".pdf", ".doc", ".docx", ".txt", ".rtf"],
        "audio": [".mp3", ".wav", ".flac", ".m4a", ".ogg"],
        "video": [".mp4", ".avi", ".mkv", ".mov", ".wmv"]
    },
    "enabled_categories": ["images"],
    "window_size": {
        "width": 700,
        "height": 500
    }
}
```