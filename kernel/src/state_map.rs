//! Ordered state maps with structural sharing and historical BTreeMap encoding.
//!
//! Clones share the root. Writes detach only AVL paths and rotation nodes; there
//! are no overlay layers to compact or scan. Tree shape is never serialized.
use borsh::{BorshDeserialize, BorshSerialize};
use std::{collections::BTreeMap, fmt, io, ops::Index, sync::Arc};

type Link<K, V> = Option<Arc<Node<K, V>>>;
#[derive(Clone)]
struct Node<K, V> {
    key: K,
    value: V,
    left: Link<K, V>,
    right: Link<K, V>,
    height: u16,
    len: usize,
}
impl<K, V> Node<K, V> {
    fn refresh(&mut self) {
        self.height = 1 + height(&self.left).max(height(&self.right));
        self.len = 1 + length(&self.left) + length(&self.right);
    }
}
fn height<K, V>(link: &Link<K, V>) -> u16 {
    link.as_ref().map_or(0, |n| n.height)
}
fn length<K, V>(link: &Link<K, V>) -> usize {
    link.as_ref().map_or(0, |n| n.len)
}

/// A canonical ordered map whose clones share unchanged branches.
///
/// Public state accessors return immutable references to this map. Mutation
/// remains subject to the containing state's kernel-only mutation interfaces.
pub struct StateMap<K, V> {
    root: Link<K, V>,
}
impl<K, V> Clone for StateMap<K, V> {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
        }
    }
}
impl<K, V> Default for StateMap<K, V> {
    fn default() -> Self {
        Self { root: None }
    }
}
impl<K, V> StateMap<K, V> {
    pub fn len(&self) -> usize {
        length(&self.root)
    }
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }
    pub fn clear(&mut self) {
        self.root = None;
    }
    pub fn iter(&self) -> Iter<'_, K, V> {
        let mut iter = Iter {
            stack: Vec::with_capacity(usize::from(height(&self.root))),
            remaining: self.len(),
        };
        iter.push_left(self.root.as_deref());
        iter
    }
    pub fn keys(&self) -> impl ExactSizeIterator<Item = &K> {
        self.iter().map(|(k, _)| k)
    }
    pub fn values(&self) -> impl ExactSizeIterator<Item = &V> {
        self.iter().map(|(_, v)| v)
    }
    pub(crate) fn shares_root(&self, other: &Self) -> bool {
        match (&self.root, &other.root) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        }
    }
}
impl<K: Ord, V> StateMap<K, V> {
    pub fn get(&self, key: &K) -> Option<&V> {
        let mut current = self.root.as_deref();
        while let Some(node) = current {
            match key.cmp(&node.key) {
                std::cmp::Ordering::Less => current = node.left.as_deref(),
                std::cmp::Ordering::Greater => current = node.right.as_deref(),
                std::cmp::Ordering::Equal => return Some(&node.value),
            }
        }
        None
    }
    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }
}
fn rotate_left<K: Clone, V: Clone>(mut root: Arc<Node<K, V>>) -> Arc<Node<K, V>> {
    let mut pivot = Arc::make_mut(&mut root)
        .right
        .take()
        .expect("AVL right child");
    let middle = Arc::make_mut(&mut pivot).left.take();
    let node = Arc::make_mut(&mut root);
    node.right = middle;
    node.refresh();
    let node = Arc::make_mut(&mut pivot);
    node.left = Some(root);
    node.refresh();
    pivot
}
fn rotate_right<K: Clone, V: Clone>(mut root: Arc<Node<K, V>>) -> Arc<Node<K, V>> {
    let mut pivot = Arc::make_mut(&mut root)
        .left
        .take()
        .expect("AVL left child");
    let middle = Arc::make_mut(&mut pivot).right.take();
    let node = Arc::make_mut(&mut root);
    node.left = middle;
    node.refresh();
    let node = Arc::make_mut(&mut pivot);
    node.right = Some(root);
    node.refresh();
    pivot
}
fn rebalance<K: Clone, V: Clone>(mut root: Arc<Node<K, V>>) -> Arc<Node<K, V>> {
    Arc::make_mut(&mut root).refresh();
    let balance = i32::from(height(&root.left)) - i32::from(height(&root.right));
    if balance > 1 {
        let left = root.left.as_ref().unwrap();
        if height(&left.left) < height(&left.right) {
            let child = Arc::make_mut(&mut root).left.take().unwrap();
            Arc::make_mut(&mut root).left = Some(rotate_left(child));
        }
        rotate_right(root)
    } else if balance < -1 {
        let right = root.right.as_ref().unwrap();
        if height(&right.right) < height(&right.left) {
            let child = Arc::make_mut(&mut root).right.take().unwrap();
            Arc::make_mut(&mut root).right = Some(rotate_right(child));
        }
        rotate_left(root)
    } else {
        root
    }
}
fn insert<K: Ord + Clone, V: Clone>(link: Link<K, V>, key: K, value: V) -> (Link<K, V>, Option<V>) {
    let Some(mut root) = link else {
        return (
            Some(Arc::new(Node {
                key,
                value,
                left: None,
                right: None,
                height: 1,
                len: 1,
            })),
            None,
        );
    };
    let order = key.cmp(&root.key);
    let node = Arc::make_mut(&mut root);
    let previous = match order {
        std::cmp::Ordering::Less => {
            let (next, previous) = insert(node.left.take(), key, value);
            node.left = next;
            previous
        }
        std::cmp::Ordering::Greater => {
            let (next, previous) = insert(node.right.take(), key, value);
            node.right = next;
            previous
        }
        std::cmp::Ordering::Equal => Some(std::mem::replace(&mut node.value, value)),
    };
    (Some(rebalance(root)), previous)
}
fn owned<K: Clone, V: Clone>(node: Arc<Node<K, V>>) -> Node<K, V> {
    Arc::try_unwrap(node).unwrap_or_else(|node| (*node).clone())
}
fn pop_min<K: Clone, V: Clone>(mut root: Arc<Node<K, V>>) -> (Link<K, V>, K, V) {
    if root.left.is_none() {
        let node = owned(root);
        return (node.right, node.key, node.value);
    }
    let node = Arc::make_mut(&mut root);
    let (left, key, value) = pop_min(node.left.take().unwrap());
    node.left = left;
    (Some(rebalance(root)), key, value)
}
fn remove<K: Ord + Clone, V: Clone>(mut root: Arc<Node<K, V>>, key: &K) -> (Link<K, V>, V) {
    let order = key.cmp(&root.key);
    if order == std::cmp::Ordering::Equal && (root.left.is_none() || root.right.is_none()) {
        let node = owned(root);
        return (node.left.or(node.right), node.value);
    }
    let node = Arc::make_mut(&mut root);
    let previous = match order {
        std::cmp::Ordering::Less => {
            let (left, previous) = remove(node.left.take().unwrap(), key);
            node.left = left;
            previous
        }
        std::cmp::Ordering::Greater => {
            let (right, previous) = remove(node.right.take().unwrap(), key);
            node.right = right;
            previous
        }
        std::cmp::Ordering::Equal => {
            let (right, key, value) = pop_min(node.right.take().unwrap());
            node.right = right;
            node.key = key;
            std::mem::replace(&mut node.value, value)
        }
    };
    (Some(rebalance(root)), previous)
}
impl<K: Ord + Clone, V: Clone> StateMap<K, V> {
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let (root, previous) = insert(self.root.take(), key, value);
        self.root = root;
        previous
    }
    pub fn remove(&mut self, key: &K) -> Option<V> {
        // Missing removals and lookups must not detach any path.
        self.get(key)?;
        let (root, previous) = remove(self.root.take().unwrap(), key);
        self.root = root;
        Some(previous)
    }
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.get(key)?;
        let mut node = Arc::make_mut(self.root.as_mut().unwrap());
        loop {
            match key.cmp(&node.key) {
                std::cmp::Ordering::Less => node = Arc::make_mut(node.left.as_mut().unwrap()),
                std::cmp::Ordering::Greater => node = Arc::make_mut(node.right.as_mut().unwrap()),
                std::cmp::Ordering::Equal => return Some(&mut node.value),
            }
        }
    }
    pub fn entry(&mut self, key: K) -> Entry<'_, K, V> {
        Entry { map: self, key }
    }
}
pub struct Entry<'a, K, V> {
    map: &'a mut StateMap<K, V>,
    key: K,
}
impl<'a, K: Ord + Clone, V: Clone + Default> Entry<'a, K, V> {
    pub fn or_default(self) -> &'a mut V {
        if !self.map.contains_key(&self.key) {
            self.map.insert(self.key.clone(), V::default());
        }
        self.map.get_mut(&self.key).unwrap()
    }
}
pub struct Iter<'a, K, V> {
    stack: Vec<&'a Node<K, V>>,
    remaining: usize,
}
impl<'a, K, V> Iter<'a, K, V> {
    fn push_left(&mut self, mut node: Option<&'a Node<K, V>>) {
        while let Some(current) = node {
            self.stack.push(current);
            node = current.left.as_deref();
        }
    }
}
impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);
    fn next(&mut self) -> Option<Self::Item> {
        let node = self.stack.pop()?;
        self.push_left(node.right.as_deref());
        self.remaining -= 1;
        Some((&node.key, &node.value))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl<K, V> ExactSizeIterator for Iter<'_, K, V> {}
impl<K, V> std::iter::FusedIterator for Iter<'_, K, V> {}
impl<'a, K, V> IntoIterator for &'a StateMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl<K: Ord, V> Index<&K> for StateMap<K, V> {
    type Output = V;
    fn index(&self, key: &K) -> &V {
        self.get(key).expect("state map key missing")
    }
}
impl<K: PartialEq, V: PartialEq> PartialEq for StateMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        if let (Some(a), Some(b)) = (&self.root, &other.root)
            && Arc::ptr_eq(a, b)
        {
            return true;
        }
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}
impl<K: Eq, V: Eq> Eq for StateMap<K, V> {}
impl<K: fmt::Debug, V: fmt::Debug> fmt::Debug for StateMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}
impl<K, V> From<BTreeMap<K, V>> for StateMap<K, V> {
    fn from(map: BTreeMap<K, V>) -> Self {
        fn build<K, V>(items: &mut impl Iterator<Item = (K, V)>, len: usize) -> Link<K, V> {
            if len == 0 {
                return None;
            }
            let left = build(items, len / 2);
            let (key, value) = items.next().unwrap();
            let right = build(items, len - len / 2 - 1);
            let mut node = Node {
                key,
                value,
                left,
                right,
                height: 0,
                len: 0,
            };
            node.refresh();
            Some(Arc::new(node))
        }
        let len = map.len();
        Self {
            root: build(&mut map.into_iter(), len),
        }
    }
}
impl<K: Ord, V> FromIterator<(K, V)> for StateMap<K, V> {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        BTreeMap::from_iter(iter).into()
    }
}
impl<K: BorshSerialize, V: BorshSerialize> BorshSerialize for StateMap<K, V> {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        let len = u32::try_from(self.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "state map too large"))?;
        len.serialize(writer)?;
        for (key, value) in self {
            key.serialize(writer)?;
            value.serialize(writer)?;
        }
        Ok(())
    }
}
impl<K: Ord + BorshDeserialize, V: BorshDeserialize> BorshDeserialize for StateMap<K, V> {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        Ok(BTreeMap::deserialize_reader(reader)?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn audit<K: Ord, V>(link: &Link<K, V>, lower: Option<&K>, upper: Option<&K>) -> (u16, usize) {
        let Some(node) = link else {
            return (0, 0);
        };
        assert!(lower.is_none_or(|key| key < &node.key));
        assert!(upper.is_none_or(|key| &node.key < key));
        let (left_height, left_len) = audit(&node.left, lower, Some(&node.key));
        let (right_height, right_len) = audit(&node.right, Some(&node.key), upper);
        assert!(left_height.abs_diff(right_height) <= 1);
        assert_eq!(node.height, 1 + left_height.max(right_height));
        assert_eq!(node.len, 1 + left_len + right_len);
        (node.height, node.len)
    }
    fn check(map: &StateMap<u64, u64>, model: &BTreeMap<u64, u64>) {
        audit(&map.root, None, None);
        assert_eq!(map.len(), model.len());
        assert_eq!(
            map.iter().collect::<Vec<_>>(),
            model.iter().collect::<Vec<_>>()
        );
        let bytes = borsh::to_vec(map).unwrap();
        assert_eq!(bytes, borsh::to_vec(model).unwrap());
        let restored = StateMap::<u64, u64>::try_from_slice(&bytes).unwrap();
        audit(&restored.root, None, None);
        assert_eq!(&restored, map);
    }
    #[test]
    fn generated_operations_forks_restore_and_encoding_match_btree_map() {
        for seed in 1..=24u64 {
            let mut random = seed;
            let mut map = StateMap::default();
            let mut model = BTreeMap::new();
            let mut forks = Vec::new();
            for step in 0..1024 {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                let key = random % 128;
                match random % 4 {
                    0 | 1 => assert_eq!(map.insert(key, random), model.insert(key, random)),
                    2 => assert_eq!(map.remove(&key), model.remove(&key)),
                    _ => {
                        if let Some(value) = map.get_mut(&key) {
                            *value ^= random;
                        }
                        if let Some(value) = model.get_mut(&key) {
                            *value ^= random;
                        }
                    }
                }
                if step % 64 == 0 {
                    forks.push((map.clone(), model.clone()));
                }
                check(&map, &model);
            }
            for (mut fork, mut expected) in forks {
                check(&fork, &expected);
                fork.insert(999, seed);
                expected.insert(999, seed);
                check(&fork, &expected);
            }
            check(&map, &model);
        }
    }
    #[test]
    fn monotonic_inserts_deletes_and_different_shapes_preserve_balance_and_bytes() {
        let mut ascending = StateMap::default();
        let mut descending = StateMap::default();
        let model: BTreeMap<_, _> = (0..4096).map(|key| (key, key * 2)).collect();
        for (&key, &value) in &model {
            ascending.insert(key, value);
        }
        for (&key, &value) in model.iter().rev() {
            descending.insert(key, value);
        }
        check(&ascending, &model);
        check(&descending, &model);
        assert_eq!(ascending, descending);
        let original = ascending.clone();
        let mut remaining = model.clone();
        for key in (0..4096).step_by(2).chain((1..4096).rev().step_by(2)) {
            assert_eq!(ascending.remove(&key), remaining.remove(&key));
            audit(&ascending.root, None, None);
        }
        check(&ascending, &remaining);
        assert!(ascending.is_empty());
        check(&original, &model);
    }
    struct Counted {
        value: u64,
        clones: Arc<AtomicUsize>,
    }
    impl Clone for Counted {
        fn clone(&self) -> Self {
            self.clones.fetch_add(1, Ordering::Relaxed);
            Self {
                value: self.value,
                clones: self.clones.clone(),
            }
        }
    }
    #[test]
    fn first_write_and_nested_owner_index_copy_paths_instead_of_whole_tables() {
        let clones = Arc::new(AtomicUsize::new(0));
        let original: StateMap<_, _> = (0..131_072u64)
            .map(|key| {
                (
                    key,
                    Counted {
                        value: key,
                        clones: clones.clone(),
                    },
                )
            })
            .collect();
        let mut staged = original.clone();
        assert_eq!(clones.load(Ordering::Relaxed), 0);
        staged.insert(
            200_000,
            Counted {
                value: 7,
                clones: clones.clone(),
            },
        );
        assert!(clones.load(Ordering::Relaxed) < 128);
        clones.store(0, Ordering::Relaxed);
        staged.get_mut(&65_536).unwrap().value = 99;
        assert!(clones.load(Ordering::Relaxed) < 128);
        clones.store(0, Ordering::Relaxed);
        staged.remove(&65_535);
        assert!(clones.load(Ordering::Relaxed) < 128);
        assert_eq!(original.get(&65_536).unwrap().value, 65_536);
        assert!(original.get(&65_535).is_some());
        assert!(original.get(&200_000).is_none());
        audit(&original.root, None, None);
        audit(&staged.root, None, None);
        let mut index = StateMap::default();
        index.insert(1u64, original);
        let mut fork = index.clone();
        clones.store(0, Ordering::Relaxed);
        fork.entry(1).or_default().remove(&42);
        assert!(clones.load(Ordering::Relaxed) < 128);
        assert!(index.get(&1).unwrap().get(&42).is_some());
    }
    #[test]
    fn missing_mutations_and_malformed_encoding_do_not_change_state() {
        let mut map: StateMap<u64, u64> = [(1, 2), (3, 4)].into_iter().collect();
        let before = map.clone();
        assert_eq!(map.remove(&9), None);
        assert_eq!(map.get_mut(&9), None);
        assert!(map.shares_root(&before));
        let bytes = borsh::to_vec(&map).unwrap();
        for len in 0..bytes.len() {
            assert!(StateMap::<u64, u64>::try_from_slice(&bytes[..len]).is_err());
        }
        map.clear();
        assert!(map.is_empty());
        assert_eq!(
            borsh::to_vec(&map).unwrap(),
            borsh::to_vec(&BTreeMap::<u64, u64>::new()).unwrap()
        );
        assert_eq!(before.len(), 2);
    }
}
