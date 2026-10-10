//! Who may answer a request: polkit's `identities`, as names a person
//! picks from.
//!
//! polkitd passes the identities its rules allow — on Arch, by default,
//! "any member of `wheel`" for administrator actions, which arrives as a
//! `unix-group`, and the requesting user for self-authentication, as a
//! `unix-user`. A group is not something one can type a password for, so
//! it is expanded into its members here, the way polkit's own agents do.
//!
//! The order is the decision that matters: whoever is sitting at the
//! session comes first when they are allowed at all, because that is the
//! answer nine times in ten and the prompt opens on the first.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

/// One identity, as polkit names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    User(u32),
    Group(u32),
}

/// The usernames that may answer, in the order to offer them: `me`
/// first when allowed, then the rest as polkit listed them, each once.
/// `name_of` and `members_of` are the system's lookups, passed in so
/// this can be tested without a passwd database.
pub fn choices(
    identities: &[Identity],
    me: &str,
    name_of: impl Fn(u32) -> Option<String>,
    members_of: impl Fn(u32) -> Vec<String>,
) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for identity in identities {
        let found = match identity {
            Identity::User(uid) => name_of(*uid).into_iter().collect(),
            Identity::Group(gid) => members_of(*gid),
        };
        for name in found {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    if let Some(at) = names.iter().position(|n| n == me) {
        let me = names.remove(at);
        names.insert(0, me);
    }
    names
}

/// The username for `uid`, from the name service — never by reading
/// `/etc/passwd`, which is wrong for LDAP, SSSD or systemd-homed users
/// (see `hyprforge-listing`'s `users` module for the longer reason).
pub fn user_name(uid: u32) -> Option<String> {
    #[repr(C)]
    struct Passwd {
        pw_name: *const c_char,
        pw_passwd: *const c_char,
        pw_uid: u32,
        pw_gid: u32,
        pw_gecos: *const c_char,
        pw_dir: *const c_char,
        pw_shell: *const c_char,
    }
    extern "C" {
        fn getpwuid_r(uid: u32, pwd: *mut Passwd, buf: *mut c_char, len: usize, result: *mut *mut Passwd) -> c_int;
    }
    with_buffer(|buf| {
        let mut pwd = std::mem::MaybeUninit::<Passwd>::uninit();
        let mut result: *mut Passwd = std::ptr::null_mut();
        // SAFETY: every pointer is to memory this frame owns, sized as
        // passed; `result` is only read when the call says it filled it.
        let rc = unsafe { getpwuid_r(uid, pwd.as_mut_ptr(), buf.as_mut_ptr(), buf.len(), &mut result) };
        match rc {
            0 if result.is_null() => Lookup::Done(None),
            // SAFETY: `result` points at `pwd`, filled, its strings in `buf`.
            0 => Lookup::Done(Some(unsafe { CStr::from_ptr((*result).pw_name) }.to_string_lossy().into_owned())),
            e if e == ERANGE => Lookup::Grow,
            _ => Lookup::Done(None),
        }
    })
    .flatten()
}

/// The members of group `gid`, from the name service. Only its listed
/// members: a user whose *primary* group it is is not listed, which is
/// also how polkit's agents expand it.
pub fn group_members(gid: u32) -> Vec<String> {
    #[repr(C)]
    struct Group {
        gr_name: *const c_char,
        gr_passwd: *const c_char,
        gr_gid: u32,
        gr_mem: *const *const c_char,
    }
    extern "C" {
        fn getgrgid_r(gid: u32, grp: *mut Group, buf: *mut c_char, len: usize, result: *mut *mut Group) -> c_int;
    }
    with_buffer(|buf| {
        let mut grp = std::mem::MaybeUninit::<Group>::uninit();
        let mut result: *mut Group = std::ptr::null_mut();
        // SAFETY: as in `user_name`.
        let rc = unsafe { getgrgid_r(gid, grp.as_mut_ptr(), buf.as_mut_ptr(), buf.len(), &mut result) };
        match rc {
            0 if result.is_null() => Lookup::Done(Vec::new()),
            0 => {
                let mut members = Vec::new();
                // SAFETY: `gr_mem` is a NULL-terminated array of C
                // strings, all inside `buf`, which outlives this loop.
                unsafe {
                    let mut at = (*result).gr_mem;
                    while !at.is_null() && !(*at).is_null() {
                        members.push(CStr::from_ptr(*at).to_string_lossy().into_owned());
                        at = at.add(1);
                    }
                }
                Lookup::Done(members)
            }
            e if e == ERANGE => Lookup::Grow,
            _ => Lookup::Done(Vec::new()),
        }
    })
    .unwrap_or_default()
}

const ERANGE: c_int = 34;

enum Lookup<T> {
    Done(T),
    Grow,
}

/// Runs a `*_r` lookup with a scratch buffer, doubling it on ERANGE up
/// to a limit — a name entry needing more than this is not a name.
fn with_buffer<T>(mut lookup: impl FnMut(&mut Vec<c_char>) -> Lookup<T>) -> Option<T> {
    let mut size = 1024;
    while size <= 256 * 1024 {
        let mut buf: Vec<c_char> = vec![0; size];
        match lookup(&mut buf) {
            Lookup::Done(value) => return Some(value),
            Lookup::Grow => size *= 2,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(uid: u32) -> Option<String> {
        match uid {
            0 => Some("root".into()),
            1000 => Some("alex".into()),
            1001 => Some("sam".into()),
            _ => None,
        }
    }

    fn wheel(_gid: u32) -> Vec<String> {
        vec!["sam".into(), "alex".into()]
    }

    /// The common case: an admin action allowed to `wheel`, asked for by
    /// a member of it — who is offered first, not whoever is first in
    /// the group file.
    #[test]
    fn the_person_at_the_session_is_offered_first() {
        assert_eq!(choices(&[Identity::Group(998)], "alex", names, wheel), ["alex", "sam"]);
    }

    #[test]
    fn a_group_is_its_members_and_nobody_is_offered_twice() {
        let ids = [Identity::User(1001), Identity::Group(998), Identity::User(0)];
        assert_eq!(choices(&ids, "nobody-here", names, wheel), ["sam", "alex", "root"]);
    }

    /// Someone who may not answer is not slipped in because they are the
    /// one asking: the list is polkit's, only its order is ours.
    #[test]
    fn the_person_at_the_session_is_not_added_when_not_allowed() {
        assert_eq!(choices(&[Identity::User(0)], "alex", names, wheel), ["root"]);
    }

    #[test]
    fn an_identity_the_system_does_not_know_is_left_out() {
        assert!(choices(&[Identity::User(4242)], "alex", names, wheel).is_empty());
    }

    /// Against this machine's own name service: uid 0 is root everywhere.
    #[test]
    fn the_real_lookup_finds_root() {
        assert_eq!(user_name(0).as_deref(), Some("root"));
    }
}
