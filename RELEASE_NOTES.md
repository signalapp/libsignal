v0.86.9

- When chat connections fail and the server's TLS response suggests a captive network or similar, there's now a dedicated error:

    - Java: PossibleCaptiveNetworkException
    - Swift: SignalError.PossibleCaptiveNetwork
    - Node: PossibleCaptiveNetworkError
