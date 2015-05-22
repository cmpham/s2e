/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

///XXX: Do not use, deprecated

extern "C" {
#include "config.h"
#include "qemu-common.h"
}

#include "InstructionCounter.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <llvm/Support/TimeValue.h>

#include <iostream>
#include <sstream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(InstructionCounter, "Instruction counter plugin", "InstructionCounter", "ExecutionTracer", "ModuleExecutionDetector");

void InstructionCounter::initialize()
{
    m_tb = NULL;

    m_executionTracer = static_cast<ExecutionTracer*>(s2e()->getPlugin("ExecutionTracer"));
    assert(m_executionTracer);

    m_executionDetector = static_cast<ModuleExecutionDetector*>(s2e()->getPlugin("ModuleExecutionDetector"));
    assert(m_executionDetector);

    //TODO: whole-system counting
    startCounter();
}




/////////////////////////////////////////////////////////////////////////////////////
void InstructionCounter::startCounter()
{
    m_executionDetector->onModuleTranslateBlockStart.connect(
            sigc::mem_fun(*this, &InstructionCounter::onTranslateBlockStart)
            );
    m_executionDetector->onModuleTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &InstructionCounter::onTranslateBlockEnd)
            );
}


/////////////////////////////////////////////////////////////////////////////////////

/**
 *  Instrument only the blocks where we want to count the instructions.
 */
void InstructionCounter::onTranslateBlockStart(
        ExecutionSignal *signal,
        2EExecutionState* state,
        const ModuleDescriptor &module,
        TranslationBlock *tb,
        uint64_t pc)
{
    if (m_tb) {
        m_tbConnection.disconnect();
    }
    m_tb = tb;

    CorePlugin *plg = s2e()->getCorePlugin();
    m_tbConnection = plg->onTranslateInstructionStart.connect(
            sigc::mem_fun(*this, &InstructionCounter::onTranslateInstructionStart)
    );

    //Get the plugin state for the current path
    DECLARE_PLUGINSTATE(InstructionCounterState, state);

    // Enalbe block hash calculation
    tb->s2e_codeBlock = (HPerfCodeBlock *)malloc(sizeof(HPerfCodeBlock));
    memcpy(tb->s2e_codeBlock->insts, &plgState->m_bCount, sizeof(plgState->m_bCount));
    tb->s2e_codeBlock->currentInstIndex = 1;
    tb->s2e_codeBlock->startPc = pc;

    //This function will flush the number of executed instructions
    signal->connect(
        sigc::mem_fun(*this, &InstructionCounter::onTraceTb)
    );
}

void InstructionCounter::onTranslateBlockEnd(
        ExecutionSignal *signal,
        S2EExecutionState* state,
        const ModuleDescriptor &module,
        TranslationBlock *tb,
        uint64_t insPc,
        bool staticTarget,
        uint64_t targetPc)
{
    signal->connect(
        sigc::mem_fun(*this, &InstructionCounter::onTraceTbEnd)
    );
}

void InstructionCounter::onTranslateInstructionStart(
        ExecutionSignal *signal,
        S2EExecutionState* state,
        TranslationBlock *tb,
        uint64_t pc)
{
    if (tb != m_tb) {
        //We've been suddenly interrupted by some other module
        m_tb = NULL;
        m_tbConnection.disconnect();
        return;
    }

    //Connect a function that will increment the number of executed
    //instructions.
    signal->connect(
        sigc::mem_fun(*this, &InstructionCounter::onTraceInstruction)
    );

}

void InstructionCounter::onModuleTranslateBlockEnd(
        ExecutionSignal *signal,
        S2EExecutionState* state,
        const ModuleDescriptor &module,
        TranslationBlock *tb,
        uint64_t endPc,
        bool staticTarget,
        uint64_t targetPc)
{
    //TRACE("%"PRIx64" StaticTarget=%d TargetPc=%"PRIx64"\n", endPc, staticTarget, targetPc);

    printf(">>>>>>>>>>> InstructionCounter::onModuleTranslateBlockEnd endPc=0x%lx, targetPc=0x%lx\n",
         endPc, targetPc);
    //Done translating the blocks, no need to instrument anymore.
    m_tb = NULL;
    m_tbConnection.disconnect();
}

/////////////////////////////////////////////////////////////////////////////////////

void InstructionCounter::onTraceTb(S2EExecutionState* state, uint64_t pc)
{
    //Get the plugin state for the current path
    DECLARE_PLUGINSTATE(InstructionCounterState, state);

    if (plgState->m_lastTbPc == pc) {
        //Avoid repeateadly tracing tight loops.
        return;
    }

    plgState->m_bCount++;
    printf(">>>>>>>>>>> InstructionCounter::onTraceTb icount=%ld, bcount=%ld, pc=0x%lx\n",
           plgState->m_iCount,
           plgState->m_bCount,
           pc);

    //Flush the counter
    ExecutionTraceICount e;
    e.count = plgState->m_iCount;
    m_executionTracer->writeData(state, &e, sizeof(e), TRACE_ICOUNT);
}

void InstructionCounter::computeXHash(S2EExecutionState* state) {
    DECLARE_PLUGINSTATE(InstructionCounterState, state);
    struct HPerfCodeBlock *cb = state->getTb()->s2e_codeBlock;

    uint64_t blockIndex;
    ihash::SHA1_CTX context;
    ihash::ShaDigest digest;

    // Copy blockIndex to the first instruction slot.
    memcpy(&blockIndex, cb->insts, sizeof(blockIndex));
    printf(">>>>>>>>>>> InstructionCounter::onTraceTbEnd icount=%ld, pc=0x%lx, currentInstIndex=%ld, blockId=%ld\n",
        plgState->m_iCount,
        pc,
        cb->currentInstIndex,
        blockIndex);
    ihash::SHA1_Init(&context);
    uint64_t cbSize = sizeof(struct HPerfInstruction) * cb->currentInstIndex;
    ihash::SHA1_Update(&context, (uint8_t*)cb->insts, cbSize);
    ihash::SHA1_Final(&context, &digest);
    ihash::SHA1_xhash(&plgState->m_xHash, &digest);

    // For debuging
    char output[80];
    ihash::digest_to_hex(&digest, output);
    printf("\t>>>>>>>>>>>> SHA1=%s returned\n", output);
    // digest_to_hex(&plgState->xHash, output);
    // printf("\t>>>>>>>>>>>> XHash=%s returned\n", output);
}

  void InstructionCounter::writeXHash(S2EExecutionState* state) {
    DECLARE_PLUGINSTATE(InstructionCounterState, state);
    ExecutionTraceXHash xh;
    memcpy(&xh.xHash, &plgState->m_xHash, sizeof(ihash::ShaDigest));
    m_executionTracer->writeData(state, &xh, sizeof(xh), TRACE_XHASH);

    // For debuging
    char output[80];
    ihash::digest_to_hex(&xh.xHash, output);
    printf("\t>>>>>>>>>>>> XHash=%s written\n", output);
  }

void InstructionCounter::onTraceTbEnd(S2EExecutionState* state, uint64_t pc)
{
    //Get the plugin state for the current path
    DECLARE_PLUGINSTATE(InstructionCounterState, state);

    if (plgState->m_lastTbPc == pc) {
        //Avoid repeateadly tracing tight loops.
        return;
    }

    if (m_perfActivated) {
      if (m_perfBlockActivated) {
        if (!m_xhashReset) {
            m_xhashReset = true;
            ihash::SHA1_initXHash(&plgState->m_xHash);
        }

        computeXHash(state);
      } else {
        if (m_xhashReset) {
          // Need to write xhash
          writeXHash(state);

          m_xhashReset = false;
        }
      }
    }
}

void InstructionCounter::onTraceInstruction(S2EExecutionState* state, uint64_t pc)
{
    //Get the plugin state for the current path
    DECLARE_PLUGINSTATE(InstructionCounterState, state);

    //Increment the instruction count
    plgState->m_iCount++;
}


/////////////////////////////////////////////////////////////////////////////////////
InstructionCounterState::InstructionCounterState()
{
    m_iCount = 0;
    m_bCount = 0;
    ihash::SHA1_initXHash(&m_xHash);
    m_lastTbPc = 0;
}

InstructionCounterState::InstructionCounterState(S2EExecutionState *s, Plugin *p)
{
    m_iCount = 0;
    m_bCount = 0;
    ihash::SHA1_initXHash(&m_xHash);
    m_lastTbPc = 0;
}

InstructionCounterState::~InstructionCounterState()
{

}

PluginState *InstructionCounterState::clone() const
{
    return new InstructionCounterState(*this);
}

PluginState *InstructionCounterState::factory(Plugin *p, S2EExecutionState *s)
{
    return new InstructionCounterState(s, p);
}

} // namespace plugins
} // namespace s2e


