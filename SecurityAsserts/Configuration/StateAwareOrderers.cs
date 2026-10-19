using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

[assembly: TestCollectionOrderer("SecurityAsserts.Configuration.StateAwareCollectionOrderer", "SecurityAsserts")]
[assembly: TestCaseOrderer("SecurityAsserts.Configuration.StateAwareCaseOrderer", "SecurityAsserts")]

namespace SecurityAsserts.Configuration;

// xUnit baraja las colecciones en cada corrida. Algunos asserts mutan datos sembrados que otros
// necesitan intactos (A19 modifica al usuario B, A21 borra su orden, A05 eleva el rol de A, A06b/A06
// promueven/borran al usuario B). Sin un orden fijo, A01/A02/A19/A21 daban veredictos distintos según
// si la mutación ocurría antes. Las pruebas que solo leen corren primero; las destructivas, al final.
public class StateAwareCollectionOrderer : ITestCollectionOrderer
{
    private static readonly string[] MutatingClasses =
    {
        "G1_IDOR_Asserts",          // A19, A21
        "G1_MassAssignment_Asserts", // A05
        "G1_BFLA_Asserts"           // A06b, A06
    };

    public IEnumerable<ITestCollection> OrderTestCollections(IEnumerable<ITestCollection> testCollections) =>
        testCollections
            .OrderBy(c => Rank(c.DisplayName))
            .ThenBy(c => c.DisplayName, StringComparer.Ordinal);

    private static int Rank(string displayName)
    {
        var index = Array.FindIndex(MutatingClasses, name => displayName.Contains(name, StringComparison.Ordinal));
        return index < 0 ? 0 : index + 1;
    }
}

public class StateAwareCaseOrderer : ITestCaseOrderer
{
    // A06b (promover) debe ir antes que A06 (borrar al usuario B).
    public IEnumerable<TTestCase> OrderTestCases<TTestCase>(IEnumerable<TTestCase> testCases)
        where TTestCase : ITestCase =>
        testCases
            .OrderBy(t => t.TestMethod.Method.Name.StartsWith("A06_", StringComparison.Ordinal) ? 1 : 0)
            .ThenBy(t => t.TestMethod.Method.Name, StringComparer.Ordinal)
            .ThenBy(t => t.UniqueID, StringComparer.Ordinal);
}
