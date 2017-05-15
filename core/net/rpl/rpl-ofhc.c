/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *         An implementation of a naive hop-count function.
 *
 * \author Henry-Joseph Audéoud <henry-joseph.audeoud@univ-grenoble-alpes.fr>
 */


#include "net/rpl/rpl-private.h"

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

static void reset(rpl_dag_t *);
static rpl_parent_t *best_parent(rpl_parent_t *, rpl_parent_t *);
static rpl_dag_t *best_dag(rpl_dag_t *, rpl_dag_t *);
static rpl_rank_t calculate_rank(rpl_parent_t *, rpl_rank_t);
static void update_metric_container(rpl_instance_t *);

rpl_of_t rpl_ofhc = {
  reset,
  NULL,
  best_parent,
  best_dag,
  calculate_rank,
  update_metric_container,
  2
};

/*---------------------------------------------------------------------------*/
static void
reset(rpl_dag_t *dag)
{
  PRINTF("RPL: Reset OF-HC\n");
}
/*---------------------------------------------------------------------------*/
static rpl_parent_t *
best_parent(rpl_parent_t *p1, rpl_parent_t *p2)
{
  rpl_dag_t *dag;
  uint16_t p1_cost;
  uint16_t p2_cost;
  int p1_is_acceptable;
  int p2_is_acceptable;

  p1_is_acceptable = (p1 != NULL);
  p2_is_acceptable = (p2 != NULL);

  if(!p1_is_acceptable) {
    return p2_is_acceptable ? p2 : NULL;
  }
  if(!p2_is_acceptable) {
    return p1_is_acceptable ? p1 : NULL;
  }

  dag = p1->dag; /* Both parents are in the same DAG. */
  p1_cost = DAG_RANK(p1->rank, p1->dag->instance) + 1;
  p2_cost = DAG_RANK(p2->rank, p2->dag->instance) + 1;

  /* Paths costs coarse-grained (multiple of min_hoprankinc), we operate without hysteresis */
  if(p1_cost != p2_cost) {
    /* Pick parent with lowest path cost */
    return p1_cost < p2_cost ? p1 : p2;
  } else {
    /* We have a tie! */
    /* Stik to current preferred parent if possible */
    if(p1 == dag->preferred_parent || p2 == dag->preferred_parent) {
      return dag->preferred_parent;
    }
    /* None of the nodes is the current preferred parent, return arbitrarilly
     * one of them. */
    return p1;
  }
}
/*---------------------------------------------------------------------------*/
static rpl_dag_t *
best_dag(rpl_dag_t *d1, rpl_dag_t *d2)
{
  if(d1->grounded != d2->grounded) {
    return d1->grounded ? d1 : d2;
  }

  if(d1->preference != d2->preference) {
    return d1->preference > d2->preference ? d1 : d2;
  }

  return d1->rank < d2->rank ? d1 : d2;
}
/*---------------------------------------------------------------------------*/
static rpl_rank_t
calculate_rank(rpl_parent_t *p, rpl_rank_t base_rank)
{
  if(base_rank == 0) {
    if(p == NULL) {
      return INFINITE_RANK;
    }
    base_rank = p->rank;
  }
  if((rpl_rank_t)(base_rank + 1) < base_rank) {
    PRINTF("RPL: OF-HC reached INFINITE_RANK\n");
    return INFINITE_RANK;
  }
  return (rpl_rank_t)(base_rank + 1);
}
/*---------------------------------------------------------------------------*/
static void
update_metric_container(rpl_instance_t *instance)
{
  instance->mc.type = RPL_DAG_MC_NONE;
}

/** @}*/

