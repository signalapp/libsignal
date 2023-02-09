//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest
import LibSignalClient

class IasTests: TestCaseBase {

    func testSignatureValidation() throws {
        let signatureData = Data(base64Encoded: goodSignature)!
        let messageData = Data(base64Encoded: goodMessage)!
        let pemBytes = Array(goodPem.utf8)

        XCTAssertTrue(Ias.verify(
                signature: signatureData,
                of: messageData,
                withCertificatesPem: pemBytes,
                at: Date()
        ))
    }

    func testBadPem() throws {
        let signatureData = Data(base64Encoded: goodSignature)!
        let messageData = Data(base64Encoded: goodMessage)!
        var pemBytes = Array(goodPem.utf8)
        pemBytes.swapAt(129, 140)

        XCTAssertFalse(Ias.verify(
                signature: signatureData,
                of: messageData,
                withCertificatesPem: pemBytes,
                at: Date()
        ))
    }

    func testBadSignature() throws {
        var signatureData = Data(base64Encoded: goodSignature)!
        signatureData.reverse()
        let messageData = Data(base64Encoded: goodMessage)!
        let pemBytes = Array(goodPem.utf8)

        XCTAssertFalse(Ias.verify(
                signature: signatureData,
                of: messageData,
                withCertificatesPem: pemBytes,
                at: Date()
        ))
    }

    func testFutureDate() throws {
        let signatureData = Data(base64Encoded: goodSignature)!
        let messageData = Data(base64Encoded: goodMessage)!
        let pemBytes = Array(goodPem.utf8)

        XCTAssertFalse(Ias.verify(
                signature: signatureData,
                of: messageData,
                withCertificatesPem: pemBytes,
                at: .distantFuture
        ))
    }

    private let goodSignature = "Hj4zz2gLX+g1T4avpcpXxmBqI5bpKKLOy4HLCTO0PwKcV+Q3fhDJVuVy0+SEgzC1TlmARKyH/DVynWu3pA9FA+4BvZxb7nLbaMG4PXdYu56sHDCzFVPsm9TPgqsVu5PbVXatZQ0oVxMkzKtPae3fy/ootXkG+4ahOU6Hwqa0Uy6+HYzL2CJZRJjHV6/iZjgTLjYsQqS0mZiaUuFoqn8RRb8/f7/9SujDSLa8dmKBqaZCtZpeHh4posLWjOhTJx07FhBRh5EV01gXFfys56h2NTc7MpmYbzt2onfH/3lDM8DfdNUJl0TfikzJyVdLWXi0MyAS2nrRhHFwVp365FYEJg=="

    private let goodMessage = "eyJpZCI6IjUyODQwOTg3NDQxNjA3OTk4Njg4MDQxMDE2MDQ3NDE2ODYwMDMiLCJ0aW1lc3RhbXAiOiIyMDE4LTA3LTE5VDE5OjU4OjI3LjUwNDEwMSIsImlzdkVuY2xhdmVRdW90ZVN0YXR1cyI6IkdST1VQX09VVF9PRl9EQVRFIiwicGxhdGZvcm1JbmZvQmxvYiI6IjE1MDIwMDY1MDQwMDAxMDAwMDA1MDUwMjA0MDEwMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDcwMDAwMDYwMDAwMDAwMjAwMDAwMDAwMDAwMDBBREZFQjYxNDI0RDY5QTc3N0U3RkFCRjNBMDMzQUJFMzYyMjcwQzZDMjAxQzUzQzk1REY1NzU4NUU0MjIyQkJEOEE3NDg3NjkyNTlBNTM3QzA0NEVGQjQwREY3NzMzQkQ5QTQzRjk1NDU5MkY2MkRCMEJFNzgyNEUwNjMzQkJFQkQ4MyIsImlzdkVuY2xhdmVRdW90ZUJvZHkiOiJBZ0FBQU44S0FBQUhBQVlBQUFBQUFHTnpvZktCVTdQMGtmQUY4bnAwbW9BdmN6NjU3bjM2Vm9WV2FkeDdySkNuQkFUL0JQLy9BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUJ3QUFBQUFBQUFBSEFBQUFBQUFBQU0xcy9EUXBON0k3RzkwN3Y1Y2hxbFlWckovMUNuWEZVbjFFSE5NbmFDYkpBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFCYmZ4VHRkbEFxU0FtS29ZbmFsV0IyODN3RDZQa2tPdWFYUXA1d296VURUUUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBRDVkZXM4c2ZmbmU2WVo4QkpIY1BSTGpQY0VVczU4VmdDelpXVVBPVXF0YXdBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifQ=="

    private let goodPem = """
        -----BEGIN CERTIFICATE-----
        MIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV
        BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV
        BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0
        YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIw
        MDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1Nh
        bnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwk
        SW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG
        9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+t
        beCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtId
        cv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuv
        LUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhA
        ImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8
        gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGh
        MB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIG
        wDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVk
        c2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJl
        cG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4r
        Rq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9
        lpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYv
        WLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUd
        ZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY
        6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW7
        2uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2
        tQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbq
        d4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV
        BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV
        BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0
        YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy
        MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL
        U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD
        DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G
        CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e
        LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh
        rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT
        L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe
        NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ
        byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H
        afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf
        6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM
        RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX
        MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50
        L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW
        BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr
        NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq
        hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir
        IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ
        sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi
        zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra
        Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA
        152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB
        3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O
        DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv
        DaVzWh5aiEx+idkSGMnX
        -----END CERTIFICATE-----
        """
}
