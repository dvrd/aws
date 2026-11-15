"""Plan-local private bounded capture with explicit waitable-child ownership."""
from dataclasses import dataclass,field
import errno,os,selectors,signal,subprocess,time

class ReservationLost(Exception):pass
class MetadataFailure(Exception):
    def __init__(self,kind):self.kind=kind


def failure_type(error):
    if isinstance(error,ReservationLost):return 'ReservationLost'
    if isinstance(error,MetadataFailure):return error.kind
    if isinstance(error,PermissionError):return 'PermissionDenied'
    if isinstance(error,(TimeoutError,subprocess.TimeoutExpired)):return 'Deadline'
    if isinstance(error,OSError):return 'OSFailure'
    return 'Other'


def observe(pid):
    try:return os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
    except OSError as error:
        if error.errno==errno.ECHILD or isinstance(error,ChildProcessError):raise ReservationLost() from None
        raise


def reap(child,deadline):
    # Explicit waitpid never synthesizes Popen.wait's returncode0 on ECHILD.
    while True:
        try:pid,status=os.waitpid(child.pid,os.WNOHANG)
        except OSError as error:
            if error.errno==errno.ECHILD or isinstance(error,ChildProcessError):raise ReservationLost() from None
            raise
        if pid==child.pid:
            code=os.waitstatus_to_exitcode(status);child.returncode=code;return code
        if time.monotonic()>=deadline:raise TimeoutError()
        time.sleep(.005)


def disown(child):
    # Reservation was lost; suppress Popen destructor's automatic poll/wait.
    # This impossible private sentinel is NEVER a reported/verified exit status.
    child.returncode=-255


@dataclass
class Captured:
    phase:str='Spawn'
    failure_type:str='None'
    cleanup_failure_type:str='None'
    returncode:int|None=None
    pid:int|None=None
    wait_state:str='NotSpawned'
    reservation_state:str='NotSpawned'
    stdout:bytes=field(default=b'',repr=False)
    stderr:bytes=field(default=b'',repr=False)
    @property
    def completed(self):
        return (self.phase=='Completed' and self.failure_type=='None' and
                self.cleanup_failure_type=='None' and self.wait_state=='VerifiedReaped' and
                self.reservation_state=='Reaped' and type(self.returncode) is int)
    def safe(self):
        return dict(phase=self.phase,failure_type=self.failure_type,
            cleanup_failure_type=self.cleanup_failure_type,returncode=self.returncode,
            pid=self.pid,wait_state=self.wait_state,reservation_state=self.reservation_state)


def live_members(pgid,deadline=None):
    """Fixed bounded ps metadata; every close fault is contained until owner retirement."""
    retirement_limit=deadline if deadline is not None else time.monotonic()+4
    deadline=min(time.monotonic()+2,retirement_limit)
    child=subprocess.Popen(['/bin/ps','-axo','pid=,pgid=,uid=,stat='],stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
    selector=None;data=bytearray();error_kind=None;held=True;code=None;allow_signal=True
    try:
        selector=selectors.DefaultSelector();selector.register(child.stdout,selectors.EVENT_READ)
        while selector.get_map():
            if time.monotonic()>=deadline:raise TimeoutError()
            for key,_ in selector.select(.05):
                chunk=os.read(key.fd,4096)
                if not chunk:selector.unregister(key.fileobj);continue
                if len(data)+len(chunk)>131072:raise RuntimeError()
                data.extend(chunk)
        while True:
            try:state=observe(child.pid)
            except ReservationLost:raise
            except BaseException:
                allow_signal=False;raise
            if state is not None:break
            if time.monotonic()>=deadline:raise TimeoutError()
            time.sleep(.005)
    except BaseException as error:
        error_kind=failure_type(error)
        if isinstance(error,ReservationLost):held=False;disown(child)
    finally:
        for resource in (selector,child.stdout):
            if resource is not None:
                try:resource.close()
                except BaseException as error:
                    if error_kind is None:error_kind=failure_type(error)
        state=None
        if held and allow_signal:
            try:state=observe(child.pid)
            except ReservationLost:
                held=False;error_kind='ReservationLost';disown(child)
            except BaseException as error:
                allow_signal=False;error_kind=failure_type(error)
        if held:
            try:
                # Fixed ps has no descendants; only its held live PID can be signalled.
                if allow_signal and state is None:os.kill(child.pid,signal.SIGKILL)
            except BaseException as error:
                if error_kind is None:error_kind=failure_type(error)
            finally:
                try:code=reap(child,min(retirement_limit,time.monotonic()+2))
                except BaseException as error:
                    if isinstance(error,ReservationLost):held=False;disown(child)
                    if error_kind is None:error_kind=failure_type(error)
    if error_kind is not None or code!=0:raise MetadataFailure(error_kind or 'Other')
    result=[]
    for line in data.decode('ascii',errors='strict').splitlines():
        parts=line.split()
        if len(parts)!=4:raise MetadataFailure('Other')
        pid,group,uid=map(int,parts[:3])
        if group==pgid and not parts[3].startswith('Z'):
            if uid!=os.getuid():raise MetadataFailure('Other')
            result.append(pid)
    return result


def capture(argv,env,deadline,limit=16384):
    result=Captured();child=None;selector=None;buffers=[bytearray(),bytearray()];held=False;allow_signal=True
    try:
        if time.monotonic()>=deadline:result.failure_type='Deadline';return result
        child=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        held=True;result.pid=child.pid;result.wait_state='Unverified';result.reservation_state='Held'
        result.phase='Read';selector=selectors.DefaultSelector()
        for index,stream in enumerate((child.stdout,child.stderr)):
            selector.register(stream,selectors.EVENT_READ,index)
        while selector.get_map():
            if time.monotonic()>=deadline:raise TimeoutError()
            for key,_ in selector.select(min(.1,max(0,deadline-time.monotonic()))):
                data=os.read(key.fd,4096)
                if not data:selector.unregister(key.fileobj);continue
                if sum(map(len,buffers))+len(data)>limit:result.failure_type='OutputLimit';break
                buffers[key.data].extend(data)
            if result.failure_type!='None':break
        if result.failure_type=='None':
            result.phase='Wait'
            while True:
                try:state=observe(child.pid)
                except ReservationLost:raise
                except BaseException:
                    allow_signal=False;raise
                if state is not None:break
                if time.monotonic()>=deadline:raise TimeoutError()
                time.sleep(.005)
    except BaseException as error:
        if result.failure_type=='None':result.failure_type=failure_type(error)
        if isinstance(error,ReservationLost):held=False;result.reservation_state='Lost';disown(child)
    finally:
        if selector is not None:
            try:selector.close()
            except BaseException as error:result.cleanup_failure_type=failure_type(error)
        if child is not None:
            retirement_deadline=time.monotonic()+5
            if held:
                if child.returncode is not None:
                    held=False;result.reservation_state='Lost';disown(child)
                    result.failure_type='ReservationLost'
                elif allow_signal:
                    try:observe(child.pid)
                    except ReservationLost:
                        held=False;result.reservation_state='Lost';disown(child)
                        result.failure_type='ReservationLost'
                    except BaseException as error:
                        allow_signal=False;result.cleanup_failure_type=failure_type(error)
            if held:
                try:
                    if allow_signal and live_members(child.pid,retirement_deadline):os.killpg(child.pid,signal.SIGKILL)
                except BaseException as error:result.cleanup_failure_type=failure_type(error)
                finally:
                    try:
                        result.returncode=reap(child,retirement_deadline)
                        result.wait_state='VerifiedReaped';result.reservation_state='Reaped'
                    except BaseException as error:
                        result.wait_state='Unverified'
                        if isinstance(error,ReservationLost):
                            result.reservation_state='Lost';disown(child);result.failure_type='ReservationLost'
                        if result.cleanup_failure_type=='None':result.cleanup_failure_type=failure_type(error)
            for stream in (child.stdout,child.stderr):
                try:stream.close()
                except BaseException as error:
                    if result.cleanup_failure_type=='None':result.cleanup_failure_type=failure_type(error)
        if result.failure_type=='None' and result.cleanup_failure_type!='None':
            result.phase='Cleanup';result.failure_type=result.cleanup_failure_type
        if result.failure_type=='None' and time.monotonic()>=deadline:
            result.phase='Wait';result.failure_type='Deadline'
        if result.failure_type=='None' and result.wait_state=='VerifiedReaped':
            result.phase='Completed';result.stdout=bytes(buffers[0]);result.stderr=bytes(buffers[1])
    return result
