using System.Runtime.Versioning;

namespace Skakel.VirtualCamera.Tests;

[SupportedOSPlatform("windows")]
public sealed class SkakelVirtualCameraTests
{
    // Only refusals: each is checked before Windows is called, so these tests never create a camera.
    [Theory]
    [InlineData("", 1280, 720, 30)]
    [InlineData("Cam", 1279, 720, 30)]
    [InlineData("Cam", 8, 8, 30)]
    [InlineData("Cam", 1280, 720, 0)]
    [InlineData("Cam", 1280, 720, 240)]
    public void Create_refuses_a_name_size_or_rate_out_of_range(string name, int width, int height, int fps)
    {
        var act = () => SkakelVirtualCamera.Create(new SkakelVirtualCameraOptions(name, width, height, fps));

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Create_refuses_an_idle_timeout_out_of_range()
    {
        var options = new SkakelVirtualCameraOptions("Cam", 1280, 720, 30) { IdleTimeout = TimeSpan.FromMinutes(5) };

        var act = () => SkakelVirtualCamera.Create(options);

        act.Should().Throw<ArgumentException>().WithMessage("*idle timeout*");
    }

    [Fact]
    public void Options_default_to_a_two_second_idle_timeout()
    {
        new SkakelVirtualCameraOptions("Cam", 1280, 720, 30).IdleTimeout.Should().Be(TimeSpan.FromSeconds(2));
    }
}
