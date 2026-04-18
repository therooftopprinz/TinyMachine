class TinyMachineReg<string n> : Register<n>;

def A : TinyMachineReg<"a">;
def B : TinyMachineReg<"b">;
def C : TinyMachineReg<"c">;
def D : TinyMachineReg<"d">;
def E : TinyMachineReg<"e">;
def F : TinyMachineReg<"f">;
def G : TinyMachineReg<"g">;
def H : TinyMachineReg<"h">;
def I : TinyMachineReg<"i">;
def J : TinyMachineReg<"j">;
def K : TinyMachineReg<"k">;
def L : TinyMachineReg<"l">;
def M : TinyMachineReg<"m">;
def N : TinyMachineReg<"n">;
def O : TinyMachineReg<"o">;
def P : TinyMachineReg<"p">;
def Q : TinyMachineReg<"q">;
def R : TinyMachineReg<"r">;
def S : TinyMachineReg<"s">;
def T : TinyMachineReg<"t">;
def U : TinyMachineReg<"u">;
def V : TinyMachineReg<"v">;
def W : TinyMachineReg<"w">;
def X : TinyMachineReg<"x">;
def Y : TinyMachineReg<"y">;
def Z : TinyMachineReg<"z">;

def GPR64 : RegisterClass<"TinyMachine", [i64], 64,
  (add A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z)>;
