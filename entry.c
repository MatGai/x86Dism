#include <stdio.h>
#include <assert.h>

// long mode 64-bit with 32-bit effective address requires size prefix (67h)

// long mode 64-bit default size is 32bits

// 16 bit operands must use prefix 66h

// to access full 64 bits, must use rex prefix

// 1 byte legacy sequence starts with 0Fh

// there are three two-byte legacy sequences: 0F 0F, 0F 38 and 0F 3A. 0F 0F is for 3DNow!
// 0F 38 and 0F 3A are used to encode extended instructions (SEE) maps.

// opcodes can be followed by modrm, then by a SIB. 

// ------ LEGACY PREFIX GROUP --------

// Operand size override 66h (changes default operand/register size)
// Address size override 67h (changes default address size)
// Segment override 2Eh = CS, 3Eh = DS, 26h = ES, 64h = FS, 65h = GS, 36h = SS 
//                                                  ( depending on prefix is the segment register to use as memory operand  )
// Lock F0h = LOCK ( certain memory r/w instructions must happen atomically )
// Repeat F3h = REP ( rep string op - ins, movs - until rCX is = 0 ), F3h = REPZ ( rep cmp string - cmpsx - until rCX = 0 or ZF = 0 ), 
//                                                  F2h = REPNZ ( rep cmp string - cmpsx - until rCX = 0 or ZF = 1 )
// -----------------------------------

// for 64 bit operands REX.w has to be set, which takes precedence over 66h prefix

// instructions accessing non-stack memory is the same as current mode i.e. 64-bit long mode would use 64-bit addressing,
//                                                  unless 67h prefix is used to specify 32-bit addressing.     


// instruction flow for x86 64-bit systems is prefix->opcode bytes-> modrm/sib/disp/imm 

// ----- REX ------
// Rex occupies range 40h - 4Fh.

typedef union _REX_DESCRIPTOR
{
    unsigned char Value;
    struct
    {
        unsigned char B : 1;        // extension of ModRM r/m field, SIB base field, or Opcode reg field
        unsigned char X : 1;        // extension of SIB index field
        unsigned char R : 1;        // extension of ModRM reg field
        unsigned char W : 1;        // 1 = 64 bit operand size
        unsigned char Reserved : 4; // must be 0100b
    };
} REX_DESCRIPTOR, * PREX_DESCRIPTOR;

static_assert(sizeof(REX_DESCRIPTOR) == 1, "REX_DESCRIPTOR size must be one byte");
// ----------------


// ----- ModRM -----

typedef union _MODRM_DESCRIPTOR
{
    unsigned char Value;
    struct
    {
        unsigned char Rm  : 3; // register/memory operand, 
        unsigned char Reg : 3; // register operand specifies register, or extend operation encoding
        unsigned char Mod : 2; // addressing mode, 11b is for register operand. Less than 11b is for memory operand with possible displacement
    };
} MODRM_DESCRIPTOR, * PMODRM_DESCRIPTOR;

static_assert(sizeof(MODRM_DESCRIPTOR) == 1, "MODRM_DESCRIPTOR size must be one byte");

// modrm reg and rm encodings

// if  ModRM.RM != 11b: 
const char* ModRmRegEncoding[8] =
{
    "rAX",  // 000b
    "rCX",  // 001b
    "rDX",  // 010b
    "rBX",  // 011b
    "SIB",  // 100b
    "rBP",  // 101b
    "rSI",  // 110b
    "rDI"   // 111b
};

// -----------------

// ----- SIB -----


typedef union _SIB_DESCRIPTOR
{
    unsigned char Value;
    struct
    {
        unsigned char Base  : 3; // base register
        unsigned char Index : 3; // index register
        unsigned char Scale : 2; // scale factor
    };

} SIB_DESCRIPTOR, * PSIB_DESCRIPTOR;

static_assert(sizeof(SIB_DESCRIPTOR) == 1, "SIB_DESCRIPTOR size must be one byte");

unsigned char SibScalarFactor[4] =
{
    1,
    2,
    4,
    8
};

// if ModRM.Mod != 11b and ModRM.RM == 100b then SIB is present
const char* SibBaseEncodingForRm100b[8] =
{
    "[rAX]",  // 000b
    "[rCX]",  // 001b
    "[rDX]",  // 010b
    "[rBX]",  // 011b
    "[rSP]",  // 100b
    "disp32/[rBP]+disp8/[rBP]+disp32",  // 101b
    "[rSI]",  // 110b
    "[rDI]"   // 111b
};

const char* SibIndexEncoding[8] =
{
    "[rAX]", // 000b
    "[rCX]", // 001b
    "[rDX]", // 010b
    "[rBX]", // 011b
    NULL,    // 100b  index * scale is 0
    "[rBP]", // 101b
    "[rSI]", // 110b
    "[rDI]"  // 111b
};

// indexing this map is 8 * ModRM.Mod + ModRM.Rm
const char* SibAndModOperandEncoding[32] =
{
        // ModRM.Mod == 00b
        //       ModRM.Rm:
        "[rAX]",        // 000b
        "[rCX]",        // 001b
        "[rDX]",        // 010b
        "[rBX]",        // 011b
        "SIB",          // 100b  sib follows modrm, address is scaled_index + base when base = 101b. addressing depends on modrm.mod
        "Disp32",       // 101b  
        "[rSI]",        // 110b
        "[rDI]",        // 111b
        // ModRM.Mod == 01b
        //       ModRM.Rm:
        "[rAX]+Disp8",  // 1000b
        "[rCX]+Disp8",  // 1001b
        "[rDX]+Disp8",  // 1010b
        "[rBX]+Disp8",  // 1011b
        "SIB+Disp8",    // 1100b  sib follows modrm, address is scaled_index+base+8_bit_offset, one byte displacement field gives offset.
        "[rBP]+Disp8",  // 1101b  
        "[rSI]+Disp8",  // 1110b
        "[rDI]+Disp8",  // 1111b
        // ModRM.Mod == 10b
         //       ModRM.Rm:
         "[rAX]+Disp32", // 10000b
         "[rCX]+Disp32", // 10001b
         "[rDX]+Disp32", // 10010b
         "[rBX]+Disp32", // 10011b
         "SIB+Disp32",   // 10100b  sib follows modrm, address is scaled_index+base+32_bit_offset, four byte displacement field gives offset.
         "[rBP]+Disp32", // 10101b  
         "[rSI]+Disp32", // 10110b
         "[rDI]+Disp32", // 10111b
          // ModRM.Mod == 11b
          //       ModRM.Rm:
          "AL/rAX",       // 11000b
          "CL/rCX",       // 11001b
          "DL/rDX",       // 11010b
          "BL/rBX",       // 11011b
          "AH/rSP",       // 11100b  
          "CH/rBP",       // 11101b  
          "DH/rSI",       // 11110b
          "BH/rDI"        // 11111b
};

inline
static
int
SibCaculateIndirectEffectiveAddress(
    PSIB_DESCRIPTOR Sib,
    PMODRM_DESCRIPTOR ModRm
)
{
    int ScaleFactor = SibScalarFactor[Sib->Scale];

}
// ---------------

typedef struct _PREFIX_DESCRIPTOR
{
    unsigned char Length;
    unsigned char Prefix;
    unsigned char Register;
} PREFIX_DESCRIPTOR, *PPREFIX_DESCRIPTOR;

typedef unsigned long long(*PrefixHandlerFn)( unsigned char* Data, unsigned int* Index );

unsigned long long 
RexPrefixHandler(
    unsigned char* Data,
    unsigned int*  Index
)
{
    REX_DESCRIPTOR RexPrefix = { .Value = Data[ *Index ]};

    if( RexPrefix.Reserved != 0x4 )
    {
        return 0;
    }


    (*Index)++;
    MODRM_DESCRIPTOR ModRmPrefix = { .Value = Data[ *Index ] };

    (*Index)++;
    SIB_DESCRIPTOR SibPrefix = { .Value = Data[ *Index ] };

    return 0;
}


static PrefixHandlerFn PrefixHandler[0xFF] =
{
    [0x40] = RexPrefixHandler,
    [0x41] = RexPrefixHandler,
    [0x42] = RexPrefixHandler,
    [0x43] = RexPrefixHandler,
    [0x44] = RexPrefixHandler,
    [0x45] = RexPrefixHandler,
    [0x46] = RexPrefixHandler,
    [0x47] = RexPrefixHandler,
    [0x48] = RexPrefixHandler,
    [0x49] = RexPrefixHandler,
    [0x4A] = RexPrefixHandler,
    [0x4B] = RexPrefixHandler,
    [0x4C] = RexPrefixHandler,
    [0x4D] = RexPrefixHandler,
    [0x4E] = RexPrefixHandler,
    [0x4F] = RexPrefixHandler
};

void
x86Dism(
    unsigned char* Data,
    unsigned int Size
)
{
    char CarryOn = 1;
    unsigned char CurrentByte;
    unsigned int Index = 0;

    while ( CarryOn && Index < Size )
    {
        CurrentByte = Data[ Index ];
        
        PrefixHandlerFn Handler = PrefixHandler[ CurrentByte ];

        if( Handler == NULL )
        {
            printf("Invalid prefix 0x%x\n", CurrentByte);
            Index++;
            continue;
        }


        int OldIndex = Index;

        Handler( Data, &Index );

        if(OldIndex == Index)
        {
            Index++;
            continue;
        }
    }
}

unsigned char opcodes[20] = 
{                                             
    0x48, 0x8b, 0x05, 0x1e, 0x00, 0x00, 0x00, // mov  rax, qword ptr[rip + 0x1e] 
    0x48, 0xff, 0xc0,                         // inc  rax
    0x50,                                     // push rax
    0x48, 0x8b, 0x5d, 0xf8,                   // mov  rbx, qword ptr[rbp - 8]
    0x48, 0x29, 0xd8,                         // sub  rax, rbx
    0x5b,                                     // pop  rbx
    0xc3                                      // ret
};

int
main(
    int argc,
    char* argv[]
)
{
    x86Dism( opcodes, sizeof( opcodes ) );
    return 0;
}