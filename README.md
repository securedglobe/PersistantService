# PersistantService
![](persistant%20service.gif)

A persistent Windows Service Proof of Concept, where the Service will run after Restart or Shutdown, and invoke a given software executable.

1. The service is installed.
2. The service starts the Sample App (unless it's already running). That's the 'Watch dog' mechanism.
3. If you shut down SampleApp.exe, the service will restart it, whilst keeping it running.
4. If you reboot, the service will start, wait for the first user to log in and then start SampleApp.exe under the logged-on user's session.
5. The service is uninstalled using the uninstall
