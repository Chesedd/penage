from __future__ import annotations

from penage.sandbox.docker import DockerSandbox


def test_base_args_contain_memory_swap_equal_to_memory():
    sb = DockerSandbox()
    args = sb._base_docker_run_args(cwd=None, env={"X": "1"})

    assert "--memory-swap" in args
    idx = args.index("--memory-swap")
    assert args[idx + 1] == sb.memory
    assert args[idx + 1] == "512m"


def test_base_args_memory_swap_can_be_overridden():
    sb = DockerSandbox(memory_swap="1g")
    args = sb._base_docker_run_args(cwd=None, env=None)

    idx = args.index("--memory-swap")
    assert args[idx + 1] == "1g"


def test_base_args_contain_hostname():
    sb = DockerSandbox()
    args = sb._base_docker_run_args(cwd=None, env=None)

    assert "--hostname" in args
    idx = args.index("--hostname")
    assert args[idx + 1] == "penage-sandbox"


def test_base_args_contain_init_by_default():
    sb = DockerSandbox()
    args = sb._base_docker_run_args(cwd=None, env=None)

    assert "--init" in args


def test_base_args_omit_init_when_disabled():
    sb = DockerSandbox(use_init=False)
    args = sb._base_docker_run_args(cwd=None, env=None)

    assert "--init" not in args


def test_base_args_contain_log_driver_none():
    sb = DockerSandbox()
    args = sb._base_docker_run_args(cwd=None, env=None)

    assert "--log-driver" in args
    idx = args.index("--log-driver")
    assert args[idx + 1] == "none"


def test_base_args_contain_three_ulimits():
    sb = DockerSandbox()
    args = sb._base_docker_run_args(cwd=None, env=None)

    ulimit_count = sum(1 for a in args if a == "--ulimit")
    assert ulimit_count == 3

    expected_values = {
        f"fsize={sb.ulimit_fsize}:{sb.ulimit_fsize}",
        f"nofile={sb.ulimit_nofile}:{sb.ulimit_nofile}",
        f"nproc={sb.ulimit_nproc}:{sb.ulimit_nproc}",
    }

    present_values = {
        args[i + 1] for i, a in enumerate(args) if a == "--ulimit"
    }
    assert present_values == expected_values


def test_base_args_contain_default_home_env():
    sb = DockerSandbox()
    args = sb._base_docker_run_args(cwd=None, env={"X": "1"})

    # expect "-e" "HOME=/workspace" pair to be present
    e_values = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
    assert "HOME=/workspace" in e_values


def test_base_args_include_user_env():
    sb = DockerSandbox()
    args = sb._base_docker_run_args(cwd=None, env={"X": "1"})

    e_values = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
    assert "X=1" in e_values


def test_base_args_user_home_overrides_default():
    sb = DockerSandbox()
    args = sb._base_docker_run_args(cwd=None, env={"HOME": "/custom"})

    e_values = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
    assert "HOME=/custom" in e_values
    assert "HOME=/workspace" not in e_values
