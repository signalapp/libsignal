import XCTest
@testable import SignalClientTests

XCTMain([
     testCase(ClonableHandleOwnerTests.allTests),
     testCase(PublicAPITests.allTests),
])
