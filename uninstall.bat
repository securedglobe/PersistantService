sc stop sg_persistantservice
sc delete sg_persistantservice
taskkill /f /im sampleapp.exe
taskkill /f /im sg_persistantservice.exe