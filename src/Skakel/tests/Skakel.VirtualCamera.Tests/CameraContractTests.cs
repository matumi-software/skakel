namespace Skakel.VirtualCamera.Tests;

public sealed class CameraContractTests
{
    [Fact]
    public void CameraId_gives_the_id_the_rust_producer_gives()
    {
        // skakel-vcam's contract.rs pins the same id.
        var id = CameraContract.CameraId("S-1-5-21-1004336348-1177238915-682003330-512", "Tweeling");

        id.Should().Be("313c3868b45ee1ae");
        CameraContract.SectionName(id).Should().Be(@"Global\Skakel.VirtualCamera.313c3868b45ee1ae");
    }

    [Fact]
    public void CameraId_depends_on_the_user()
    {
        CameraContract.CameraId("S-1-5-21-1", "Cam").Should().NotBe(CameraContract.CameraId("S-1-5-21-2", "Cam"));
    }

    [Fact]
    public void Fnv1a64_matches_the_reference_values()
    {
        CameraContract.Fnv1a64([]).Should().Be(0xcbf29ce484222325);
        CameraContract.Fnv1a64("a"u8).Should().Be(0xaf63dc4c8601ec8c);
        CameraContract.Fnv1a64("foobar"u8).Should().Be(0x85944171f73967e8);
    }

    [Fact]
    public void EncodeIdleFile_writes_the_header_the_source_reads()
    {
        var file = CameraContract.EncodeIdleFile(16, 16, new byte[384]);

        file.Length.Should().Be(16 + 384);
        file[..16].Should().Equal(0x53, 0x4B, 0x56, 0x49, 1, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0);
    }

    [Fact]
    public void IdleFilePath_is_under_program_data()
    {
        CameraContract.IdleFilePath("data", "313c3868b45ee1ae")
            .Should().Be(Path.Combine("data", "Skakel", "VirtualCamera", "313c3868b45ee1ae.idle"));
    }
}
