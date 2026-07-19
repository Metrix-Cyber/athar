package finding

import (
	"testing"
	"time"
)

func sample() []Finding {
	return []Finding{
		New("b.check", "B", "2-5", []string{"2-5-2"}).
			Failed(High, "something is wrong", "fix it"),
		New("a.check", "A", "2-2", []string{"2-2-2"}).
			Passed("all good"),
	}
}

func TestDigestIsDeterministicForIdenticalFindings(t *testing.T) {
	// Identical findings must digest identically. This is determinism of the
	// function, not stability across scans: a real host produces different
	// findings minutes apart because ephemeral ports come and go, so the
	// digest identifies a report rather than a machine's state.
	a := Digest(sample())
	b := Digest(sample())
	if a != b {
		t.Errorf("digest is not deterministic:\n  %s\n  %s", a, b)
	}
	if len(a) != 64 {
		t.Errorf("digest length = %d, want 64 hex characters", len(a))
	}
}

func TestDigestIgnoresObservationTime(t *testing.T) {
	// Timestamps must not contribute, or the digest would change on every run
	// regardless of findings and be useless as a reference.
	a := sample()
	b := sample()
	for i := range b {
		b[i].ObservedAt = b[i].ObservedAt.Add(time.Hour)
	}
	if Digest(a) != Digest(b) {
		t.Error("digest changed when only observation timestamps differed")
	}
}

func TestDigestIgnoresFindingOrder(t *testing.T) {
	// Check registration order is stable today but would shift if a check were
	// renamed. The digest must depend on content, not on ordering.
	fs := sample()
	reversed := []Finding{fs[1], fs[0]}
	if Digest(fs) != Digest(reversed) {
		t.Error("digest changed when findings were reordered")
	}
}

func TestDigestDetectsChangedVerdict(t *testing.T) {
	// The tampering case this exists for: flipping a failure to a pass.
	original := sample()
	tampered := sample()
	tampered[0] = tampered[0].Passed("something is wrong")

	if Digest(original) == Digest(tampered) {
		t.Error("digest did not change when a failing finding was flipped to passing")
	}
}

func TestDigestDetectsChangedSeverity(t *testing.T) {
	original := sample()
	tampered := sample()
	tampered[0] = tampered[0].Failed(Low, "something is wrong", "fix it")

	if Digest(original) == Digest(tampered) {
		t.Error("digest did not change when severity was downgraded")
	}
}

func TestDigestDetectsChangedEvidence(t *testing.T) {
	// Evidence is what makes a finding checkable; silently editing it would
	// undermine the finding without changing its verdict.
	original := sample()
	tampered := sample()
	tampered[0] = tampered[0].With("accounts", []string{"removed"})

	if Digest(original) == Digest(tampered) {
		t.Error("digest did not change when evidence was altered")
	}
}

func TestDigestDetectsRemovedFinding(t *testing.T) {
	// Deleting an inconvenient finding is the simplest tampering of all.
	original := sample()
	tampered := original[:1]

	if Digest(original) == Digest(tampered) {
		t.Error("digest did not change when a finding was removed")
	}
}

func TestDigestOfEmptyIsStable(t *testing.T) {
	if Digest(nil) != Digest([]Finding{}) {
		t.Error("nil and empty finding sets should digest identically")
	}
}
