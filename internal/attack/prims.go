package attack

// identity.adopt is registered here rather than beside the other identity
// primitives because its body sits in identity.go, with the credential store it
// reads a harvested token into.

type identityAdoptParams struct {
	Select string `yaml:"select"`
}

func init() {
	Register(Spec{
		Name:    "identity.adopt",
		Summary: "Promote a durable credential found in harvested loot into an acting identity later steps name with as:; select: picks the harvested field, and a credential with no future expiry is refused.",
		Ports:   []Port{Accepts[Loot]("loot", true)},
	}, identityAdopt)
}
